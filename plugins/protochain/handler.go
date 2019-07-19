package gabbygrove

import (
	"context"
	"fmt"
	"sync"

	"github.com/cryptix/go/logging"
	"github.com/pkg/errors"
	"go.cryptoscope.co/librarian"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/multilog"
	"go.cryptoscope.co/muxrpc"
	"go.cryptoscope.co/muxrpc/codec"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/graph"
	"go.cryptoscope.co/ssb/internal/mutil"
	"go.cryptoscope.co/ssb/message"
	"go.cryptoscope.co/ssb/message/gabbygrove"
	"go.cryptoscope.co/ssb/plugins/gossip"
)

type handler struct {
	whoami   *ssb.FeedRef
	rl       margaret.Log
	feedsIdx multilog.MultiLog
	gb       graph.Builder
	Info     logging.Interface

	hmacSec  gossip.HMACSecret
	hopCount int
	promisc  bool // ask for remote feed even if it's not on owns fetch list

	activeLock  sync.Mutex
	activeFetch sync.Map
}

func New(logger logging.Interface, whoami *ssb.FeedRef, rootLog margaret.Log, userFeeds multilog.MultiLog, gb graph.Builder, opts ...interface{}) ssb.Plugin {
	h := &handler{
		whoami:   whoami,
		rl:       rootLog,
		feedsIdx: userFeeds,
		gb:       gb,
		Info:     logger,
	}
	for i, o := range opts {
		switch v := o.(type) {
		case gossip.HopCount:
			h.hopCount = int(v)
		case gossip.HMACSecret:
			h.hmacSec = v
		case gossip.Promisc:
			h.promisc = bool(v)
		default:
			logger.Log("warning", "unhandled option", "i", i, "type", fmt.Sprintf("%T", o))
		}
	}
	if h.hopCount == 0 {
		h.hopCount = 2
	}
	return &plugin{h}
}

func (g *handler) HandleConnect(ctx context.Context, e muxrpc.Endpoint) {
	// outwards pull requests are created by (legacy) gossip plugin
}
func (g *handler) check(err error) {
	if err != nil {
		g.Info.Log("error", err)
	}
}

func (g *handler) HandleCall(ctx context.Context, req *muxrpc.Request, edp muxrpc.Endpoint) {
	if req.Type == "" {
		req.Type = "async"
	}

	closeIfErr := func(err error) {
		g.check(err)
		if err != nil {
			closeErr := req.Stream.CloseWithError(err)
			g.check(errors.Wrapf(closeErr, "error closeing request. %s", req.Method))
		}
	}

	switch req.Method.String() {

	case "protochain.binaryStream":
		if req.Type != "source" {
			closeIfErr(errors.Errorf("binaryStream: wrong tipe. %s", req.Type))
			return
		}
		if err := g.pourFeed(ctx, req); err != nil {
			closeIfErr(errors.Wrap(err, "binaryStream failed"))
			return
		}

	default:
		closeIfErr(errors.Errorf("unknown command: %s", req.Method))
	}
}

func (h *handler) pourFeed(ctx context.Context, req *muxrpc.Request) error {
	// check & parse args
	if len(req.Args) < 1 {
		return errors.New("ssb/message: not enough arguments, expecting feed id")
	}
	argMap, ok := req.Args[0].(map[string]interface{})
	if !ok {
		return errors.Errorf("ssb/message: not the right map - %T", req.Args[0])
	}
	qry, err := message.NewCreateHistArgsFromMap(argMap)
	if err != nil {
		return errors.Wrap(err, "bad request")
	}

	feedRef, err := ssb.ParseFeedRef(qry.Id)
	if err != nil {
		return nil // only handle valid feed refs
	}

	if feedRef.Algo != ssb.RefAlgoProto {
		err := errors.Errorf("please use appropriate method for other feed types")
		fmt.Println("pour:", err)
		return err
	}

	// check what we got
	userLog, err := h.feedsIdx.Get(feedRef.StoredAddr())
	if err != nil {
		return errors.Wrapf(err, "failed to open sublog for user")
	}
	latest, err := userLog.Seq().Value()
	if err != nil {
		return errors.Wrapf(err, "failed to observe latest")
	}

	// act accordingly
	switch v := latest.(type) {
	case librarian.UnsetValue: // don't have the feed - nothing to do?
	case margaret.BaseSeq:
		if qry.Seq != 0 {
			qry.Seq--               // our idx is 0 based
			if qry.Seq > int64(v) { // more than we got
				return errors.Wrap(req.Stream.Close(), "pour: failed to close")
			}
		}

		if qry.Limit == 0 {
			// currently having live streams is not tested
			// it might work but we have some problems with dangling rpc routines which we like to fix first
			qry.Limit = -1
		}

		resolved := mutil.Indirect(h.rl, userLog)
		src, err := resolved.Query(
			margaret.Gte(margaret.BaseSeq(qry.Seq)),
			margaret.Limit(int(qry.Limit)),
			margaret.Live(false),
			margaret.Reverse(qry.Reverse),
		)
		if err != nil {
			return errors.Wrapf(err, "invalid user log query seq:%d - limit:%d", qry.Seq, qry.Limit)
		}

		sent := 0
		snk := luigi.FuncSink(func(ctx context.Context, v interface{}, err error) error {
			if err != nil {
				return err
			}
			mm, ok := v.(message.MultiMessage)
			if !ok {
				return errors.Errorf("binStream: expected []byte - got %T", v)
			}
			mmv, err := mm.ByType(message.Proto)
			if err != nil {
				return errors.Wrap(err, "wrong mm type")
			}
			p := mmv.(*gabbygrove.Transfer)
			trdata, err := p.Marshal()
			if err != nil {
				return errors.Wrap(err, "failed to marshal transfer")
			}

			sent++
			return req.Stream.Pour(ctx, codec.Body(trdata))
		})

		err = luigi.Pump(ctx, snk, src)

		h.Info.Log("event", "bingossiptx", "n", sent)

		if errors.Cause(err) == context.Canceled {
			req.Stream.Close()
			return nil
		} else if err != nil {
			return errors.Wrap(err, "failed to pump messages to peer")
		}

	default:
		return errors.Errorf("wrong type in index. expected margaret.BaseSeq - got %T", latest)
	}
	return errors.Wrap(req.Stream.Close(), "pour: failed to close")
}

/* TODO: make this ProtoDrain
func NewOffchainDrain(who *ssb.FeedRef, start margaret.Seq, lastMsg message.StoredMessage, rl margaret.Log, hmac HMACSecret) luigi.Sink {
	ld := legacyDrain{
		who:       who,
		latestSeq: start,
		latestMsg: &lastMsg,
		rootLog:   rl,
		hmacSec:   hmac,
	}

	return &offchainDrain{
		legacyDrain: ld,
	}
}

type offchainDrain struct {
	legacyDrain

	consumed uint
	lastData []byte
	lastHash *ssb.OffchainMessageRef
}

func (od *offchainDrain) Pour(ctx context.Context, v interface{}) error {

	// flip-flop between content and metadata
	if od.consumed%2 == 0 {
		var ok bool
		od.lastData, ok = v.([]byte)
		if !ok {
			return errors.Errorf("binStream: expected []byte - got %T", v)
		}

		h := sha256.New()
		io.Copy(h, bytes.NewReader(od.lastData))

		od.lastHash = &ssb.OffchainMessageRef{
			Hash: h.Sum(nil),
			Algo: ssb.RefAlgoSHA256,
		}
		fmt.Println("offchain content:", od.lastHash.Ref())
		od.consumed++
		return nil
	}

	nextMsg, err := od.legacyDrain.verifyAndValidate(ctx, v)
	if err != nil {
		return errors.Wrap(err, "offchain: failed in metadata portion")
	}

	var signedRef struct {
		Content ssb.OffchainMessageRef `json:"content"`
	}
	if err := json.Unmarshal(nextMsg.Raw, &signedRef); err != nil {
		return errors.Wrap(err, "offchain: failed to parse content hash from signed message")
	}

	if !bytes.Equal(signedRef.Content.Hash, od.lastHash.Hash) {
		return errors.Errorf("offchain: missmatch between content and signed meta-data")
	}

	nextMsg.Offchain = od.lastData

	_, err = od.rootLog.Append(*nextMsg)
	if err != nil {
		return errors.Wrapf(err, "fetchFeed(%s): failed to append message(%s:%d)", od.who.Ref(), nextMsg.Key.Ref(), nextMsg.Sequence)
	}

	od.latestSeq = nextMsg.Sequence
	od.latestMsg = nextMsg
	fmt.Println("poured offchainMeta", od.latestSeq)

	od.consumed++
	return nil
}
*/
