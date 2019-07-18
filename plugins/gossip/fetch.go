package gossip

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/pkg/errors"
	"go.cryptoscope.co/librarian"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/muxrpc"
	"go.cryptoscope.co/muxrpc/codec"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/graph"
	"go.cryptoscope.co/ssb/message"
	"go.cryptoscope.co/ssb/message/legacy"
	"go.mindeco.de/protochain"
)

type ErrWrongSequence struct {
	Ref             *ssb.FeedRef
	Indexed, Stored margaret.Seq
}

func (e ErrWrongSequence) Error() string {
	return fmt.Sprintf("consistency error: wrong stored message sequence for feed %s. stored:%d indexed:%d",
		e.Ref.Ref(), e.Stored, e.Indexed)
}

func (h *handler) fetchAllLib(ctx context.Context, e muxrpc.Endpoint, lst []librarian.Addr) error {
	var refs = graph.NewFeedSet(len(lst))
	for i, addr := range lst {
		ref, err := ssb.ParseFeedRef(string(addr))
		if err != nil {
			return errors.Wrapf(err, "fetchLib(%d) failed to parse (%q)", i, addr)
		}
		if err := refs.AddRef(ref); err != nil {
			return errors.Wrapf(err, "fetchLib(%d) set add failed", i)
		}
	}
	return h.fetchAll(ctx, e, refs)
}

func (h *handler) fetchAllMinus(ctx context.Context, e muxrpc.Endpoint, fs graph.FeedSet, got []librarian.Addr) error {
	lst, err := fs.List()
	if err != nil {
		return err
	}
	var refs = graph.NewFeedSet(len(lst))
	for _, ref := range lst {
		if !isIn(got, ref) {
			err := refs.AddRef(ref)
			if err != nil {
				return err
			}
		}
	}
	return h.fetchAll(ctx, e, refs)
}

func (h *handler) fetchAll(ctx context.Context, e muxrpc.Endpoint, fs graph.FeedSet) error {
	// we don't just want them all parallel right nw
	// this kind of concurrency is way to harsh on the runtime
	// we need some kind of FeedManager, similar to Blobs
	// which we can ask for which feeds aren't in transit,
	// due for a (probabilistic) update
	// and manage live feeds more granularly across open connections

	lst, err := fs.List()
	if err != nil {
		return err
	}
	for _, r := range lst {
		err := h.fetchFeed(ctx, r, e)
		if muxrpc.IsSinkClosed(err) || errors.Cause(err) == context.Canceled {
			return err
		} else if err != nil {
			// assuming forked feed for instance
			h.Info.Log("msg", "fetchFeed stored failed", "err", err)
		}
	}
	return nil
}

func isIn(list []librarian.Addr, a *ssb.FeedRef) bool {
	for _, el := range list {
		if el == a.StoredAddr() {
			return true
		}
	}
	return false
}

// fetchFeed requests the feed fr from endpoint e into the repo of the handler
func (g *handler) fetchFeed(ctx context.Context, fr *ssb.FeedRef, edp muxrpc.Endpoint) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	// check our latest
	addr := fr.StoredAddr()
	g.activeLock.Lock()
	_, ok := g.activeFetch.Load(addr)
	if ok {
		// errors.Errorf("fetchFeed: crawl of %x active", addr[:5])
		g.activeLock.Unlock()
		return nil
	}
	if g.sysGauge != nil {
		g.sysGauge.With("part", "fetches").Add(1)
	}
	g.activeFetch.Store(addr, true)
	g.activeLock.Unlock()
	defer func() {
		g.activeLock.Lock()
		g.activeFetch.Delete(addr)
		g.activeLock.Unlock()
		if g.sysGauge != nil {
			g.sysGauge.With("part", "fetches").Add(-1)
		}
	}()
	userLog, err := g.UserFeeds.Get(addr)
	if err != nil {
		return errors.Wrapf(err, "failed to open sublog for user")
	}
	latest, err := userLog.Seq().Value()
	if err != nil {
		return errors.Wrapf(err, "failed to observe latest")
	}
	var (
		latestSeq margaret.BaseSeq
		latestMsg ssb.Message
	)
	switch v := latest.(type) {
	case librarian.UnsetValue:
		// nothing stored, fetch from zero
	case margaret.BaseSeq:
		latestSeq = v + 1 // sublog is 0-init while ssb chains start at 1
		if v >= 0 {
			rootLogValue, err := userLog.Get(v)
			if err != nil {
				return errors.Wrapf(err, "failed to look up root seq for latest user sublog")
			}
			msgV, err := g.RootLog.Get(rootLogValue.(margaret.Seq))
			if err != nil {
				return errors.Wrapf(err, "failed retreive stored message")
			}

			abs, ok := msgV.(ssb.Message)
			if !ok {
				return errors.Errorf("fetch: wrong message type. expected %T - got %T", latestMsg, msgV)
			}

			latestMsg = abs

			if hasSeq := latestMsg.Seq(); hasSeq != latestSeq.Seq() {
				return &ErrWrongSequence{Stored: latestMsg, Indexed: latestSeq, Ref: fr}
			}
		}
	}

	startSeq := latestSeq
	info := log.With(g.Info, "fr", fr.Ref(), "latest", startSeq) // "me", g.Id.Ref(), "from", ...)

	var q = message.CreateHistArgs{
		Id:    fr.Ref(),
		Seq:   int64(latestSeq + 1),
		Limit: -1,
	}
	start := time.Now()

	toLong, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer func() {
		cancel()
		if n := latestSeq - startSeq; n > 0 {
			if g.sysGauge != nil {
				g.sysGauge.With("part", "msgs").Add(float64(n))
			}
			if g.sysCtr != nil {
				g.sysCtr.With("event", "gossiprx").Add(float64(n))
			}
			info.Log("event", "gossiprx", "new", n, "took", time.Since(start))
		}
	}()

	var source luigi.Source
	var snk luigi.Sink
	if fr.Algo == ssb.RefAlgoProto {
		source, err = edp.Source(toLong, codec.Body{}, muxrpc.Method{"protochain", "binaryStream"}, q)

		snk = protochain.NewStreamDrain(fr, latestSeq, latestMsg, g.RootLog) //, g.hmacSec)
	} else {
		source, err = edp.Source(toLong, json.RawMessage{}, muxrpc.Method{"createHistoryStream"}, q)

		snk = NewLegacyDrain(fr, latestSeq, latestMsg, g.RootLog, g.hmacSec)
	}
	if err != nil {
		return errors.Wrapf(err, "fetchFeed(%s:%d) failed to create source", fr.Ref(), latestSeq)
	}

	err = luigi.Pump(toLong, snk, source)
	return errors.Wrap(err, "pump with legacy drain failed")
}

func NewLegacyDrain(who *ssb.FeedRef, start margaret.Seq, abs ssb.Message, rl margaret.Log, hmac HMACSecret) luigi.Sink {

	return &legacyDrain{
		who:       who,
		latestSeq: start,
		latestMsg: abs,
		rootLog:   rl,
		hmacSec:   hmac,
	}
}

type legacyDrain struct {
	who       *ssb.FeedRef // which feed is pulled
	latestSeq margaret.Seq
	latestMsg ssb.Message
	rootLog   margaret.Log
	hmacSec   HMACSecret
}

func (ld *legacyDrain) Pour(ctx context.Context, v interface{}) error {
	nextMsg, err := ld.verifyAndValidate(ctx, v)
	if err != nil {
		return err
	}

	mm := protochain.NewMultiMessageFromLegacy(nextMsg)

	_, err = ld.rootLog.Append(mm)
	if err != nil {
		return errors.Wrapf(err, "fetchFeed(%s): failed to append message(%s:%d)", ld.who.Ref(), nextMsg.Key().Ref(), nextMsg.Seq())
	}

	ld.latestSeq = nextMsg
	ld.latestMsg = nextMsg
	fmt.Println("poured legacyDrain", ld.latestSeq)
	return nil
}

func (ld *legacyDrain) verifyAndValidate(ctx context.Context, v interface{}) (*legacy.StoredMessage, error) {
	rmsg, ok := v.(json.RawMessage)
	if !ok {
		return nil, errors.Errorf("b4pour: expected %T - got %T", rmsg, v)
	}
	ref, dmsg, err := legacy.Verify(rmsg, ld.hmacSec)
	if err != nil {
		return nil, errors.Wrapf(err, "fetchFeed(%s:%d): message verify failed", ld.who.Ref(), ld.latestSeq)
	}

	if ld.latestSeq.Seq() > 1 {
		if bytes.Compare(ld.latestMsg.Key().Hash, dmsg.Previous.Hash) != 0 {
			return nil, errors.Errorf("fetchFeed(%s:%d): previous compare failed expected:%s incoming:%s",
				ld.who.Ref(),
				ld.latestSeq,
				ld.latestMsg.Key().Ref(),
				dmsg.Previous.Ref(),
			)
		}
		if ld.latestMsg.Seq()+1 != dmsg.Sequence.Seq() {
			return nil, errors.Errorf("fetchFeed(%s:%d): next.seq != curr.seq+1", ld.who.Ref(), ld.latestSeq)
		}
	}

	return &legacy.StoredMessage{
		Author_:    &dmsg.Author,
		Previous_:  &dmsg.Previous,
		Key_:       ref,
		Sequence_:  dmsg.Sequence,
		Timestamp_: time.Now(),
		Raw_:       rmsg,
	}, nil
}

func (ld legacyDrain) Close() error {
	fmt.Println("closing legacyDrain")
	return nil
}
