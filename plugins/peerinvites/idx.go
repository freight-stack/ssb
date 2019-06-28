package peerinvites

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/nacl/auth"

	"go.cryptoscope.co/librarian"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/multilog"

	"github.com/cryptix/go/logging"
	"github.com/dgraph-io/badger"
	"github.com/pkg/errors"
	libbadger "go.cryptoscope.co/librarian/badger"
	"go.cryptoscope.co/muxrpc"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message"
	"go.cryptoscope.co/ssb/plugins/get"
	"go.cryptoscope.co/ssb/repo"
)

type Plugin struct {
	tl multilog.MultiLog
	rl margaret.Log

	logger logging.Interface

	h handler
}

func (p Plugin) Name() string {
	return "get"
}

func (p Plugin) Method() muxrpc.Method {
	return muxrpc.Method{"peerInvites"}
}

func (p Plugin) Handler() muxrpc.Handler {
	return p.h
}

const FolderNameInvites = "peerInvites"

func (p *Plugin) OpenIndex(r repo.Interface) (librarian.Index, repo.ServeFunc, error) {
	db, sinkIdx, serve, err := repo.OpenBadgerIndex(r, FolderNameInvites, p.updateIndex)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error getting index")
	}
	nextServe := func(ctx context.Context, log margaret.Log, live bool) error {
		err := serve(ctx, log, live)
		if err != nil {
			return err
		}
		return db.Close()
	}
	return sinkIdx, nextServe, nil
}

func (p *Plugin) updateIndex(db *badger.DB) librarian.SinkIndex {
	p.h.state = libbadger.NewIndex(db, true)

	idxSink := librarian.NewSinkIndex(func(ctx context.Context, seq margaret.Seq, val interface{}, idx librarian.SetterIndex) error {
		msg, ok := val.(message.StoredMessage)
		if !ok {
			return errors.Errorf("index/invites: unexpected message type: %T", val)
		}
		var msgType struct {
			Content struct {
				Type string `json:"type"`
			} `json:"content"`
		}
		err := json.Unmarshal(msg.Raw, &msgType)
		if err != nil {
			p.logger.Log("skipped", msg.Key.Ref())
			return nil
		}

		switch msgType.Content.Type {
		case "peer-invite":
			return p.indexNewInvite(ctx, msg)
		case "peer-invite/confirm":
			return p.indexConfirm(ctx, msg)
		default:
			p.logger.Log("skipped", msg.Key.Ref(), "why", "wrong type", "type", msgType.Content.Type)
			return nil // skip
		}
	}, p.h.state)
	return idxSink
}

func (p *Plugin) indexNewInvite(ctx context.Context, msg message.StoredMessage) error {

	var invCore struct {
		Content struct {
			Invite *ssb.FeedRef `json:"invite"`
			Host   *ssb.FeedRef `json:"host"`
		} `json:"content"`
	}
	err := json.Unmarshal(msg.Raw, &invCore)
	if err != nil {
		return err
	}

	if invCore.Content.Invite == nil {
		return fmt.Errorf("invalid invite")
	}
	guestRef := invCore.Content.Invite.Ref()
	idxAddr := librarian.Addr(guestRef)

	obv, err := p.h.state.Get(ctx, idxAddr)
	if err != nil {
		return errors.Wrap(err, "idx get failed")
	}

	obvV, err := obv.Value()
	if err != nil {
		return errors.Wrap(err, "idx value failed")
	}

	switch v := obvV.(type) {
	case bool:
		return nil
		if !v { // invite was used
		} else {
			// still set?!?
		}

	case librarian.UnsetValue:
		p.logger.Log("msg", "got invite", "author", msg.Author.Ref(), "guest", guestRef)
		return p.h.state.Set(ctx, idxAddr, true)
	}
	return fmt.Errorf("unhandled index type for new invite message: %T", obvV)
}

func (p *Plugin) indexConfirm(ctx context.Context, msg message.StoredMessage) error {
	var invConfirm struct {
		Content struct {
			Embed struct {
				Content acceptContent `json:"content"`
			} `json:"embed"`
		} `json:"content"`
	}
	err := json.Unmarshal(msg.Raw, &invConfirm)
	if err != nil {
		return err
	}
	accptMsg := invConfirm.Content.Embed.Content

	if accptMsg.Receipt == nil {
		return fmt.Errorf("invalid recipt on confirm msg")
	}

	reciept, err := p.h.g.Get(*accptMsg.Receipt)
	if err != nil {
		return err
	}

	var invCore struct {
		Content struct {
			Invite *ssb.FeedRef `json:"invite"`
			Host   *ssb.FeedRef `json:"host"`
		} `json:"content"`
	}
	err = json.Unmarshal(reciept.Raw, &invCore)
	if err != nil {
		return err
	}

	idxAddr := librarian.Addr(invCore.Content.Invite.Ref())
	p.logger.Log("msg", "invite confirmed", "author", msg.Author.Ref(), "guest", idxAddr)
	return p.h.state.Set(ctx, idxAddr, false)
}

func (p *Plugin) Authorize(to *ssb.FeedRef) error {
	obv, err := p.h.state.Get(context.Background(), librarian.Addr(to.Ref()))
	if err != nil {
		return errors.Wrap(err, "idx state get failed")
	}
	v, err := obv.Value()
	if err != nil {
		return errors.Wrap(err, "idx value failed")
	}
	if valid, ok := v.(bool); ok && valid {
		p.logger.Log("authorized", "auth", "to", to.Ref())
		return nil
	}
	return errors.New("not for us")
}

var (
	_ ssb.Plugin     = (*Plugin)(nil)
	_ ssb.Authorizer = (*Plugin)(nil)
)

func New(logger logging.Interface, g get.Getter, typeLog multilog.MultiLog, rootLog, publishLog margaret.Log) *Plugin {
	p := Plugin{
		logger: logger,

		tl: typeLog,
		rl: rootLog,

		h: handler{
			g:   g,
			tl:  typeLog,
			rl:  rootLog,
			pub: publishLog,
		},
	}

	return &p
}

type handler struct {
	state librarian.SeqSetterIndex

	g get.Getter

	tl multilog.MultiLog
	rl margaret.Log

	pub margaret.Log
}

func (h handler) HandleConnect(ctx context.Context, e muxrpc.Endpoint) {}

func (h handler) HandleCall(ctx context.Context, req *muxrpc.Request, edp muxrpc.Endpoint) {
	if len(req.Args()) < 1 {
		req.CloseWithError(errors.Errorf("invalid arguments"))
		return
	}

	guestRef, err := ssb.GetFeedRefFromAddr(edp.Remote())
	if err != nil {
		req.CloseWithError(errors.Wrap(err, "no guest ref!?"))
		return
	}

	switch req.Method.String() {
	case "peerInvites.willReplicate":
		// addtional graph dist check?
		// we know they are in range since the default graph check
		// but could be played with different values for each..
		req.Return(ctx, true)
		// req.CloseWithError(fmt.Errorf("sorry"))
	case "peerInvites.getInvite":
		ref, err := ssb.ParseMessageRef(req.Args()[0].(string))
		if err != nil {
			req.CloseWithError(errors.Wrap(err, "failed to parse arguments"))
			return
		}
		msg, err := h.g.Get(*ref)
		if err != nil {
			req.CloseWithError(errors.Wrap(err, "failed to load message"))
			return
		}

		// invite data matches
		var invCore struct {
			Content struct {
				Invite *ssb.FeedRef `json:"invite"`
				Host   *ssb.FeedRef `json:"host"`
			} `json:"content"`
		}
		err = json.Unmarshal(msg.Raw, &invCore)
		if err != nil {
			req.CloseWithError(errors.Wrap(err, "failed to load message"))
			return
		}

		if !bytes.Equal(invCore.Content.Invite.ID, guestRef.ID) {
			req.CloseWithError(errors.Errorf("not your invite"))
			return
		}

		err = req.Return(ctx, message.RawSignedMessage{msg.Raw})
		if err != nil {
			fmt.Println("get: failed to return message:", err)
			return
		}

	case "peerInvites.confirm":

		// shady way to check that its an array with 1 elem
		msgArg := bytes.TrimSuffix([]byte(req.RawArgs), []byte("]"))
		msgArg = bytes.TrimPrefix(msgArg, []byte("["))

		content, err := verifyAcceptMessage(msgArg, guestRef)
		if err != nil {
			req.CloseWithError(errors.Wrap(err, "failed to validate accept msg"))
			return
		}

		seq, err := h.pub.Append(struct {
			Type  string          `json:"type"`
			Embed json.RawMessage `json:"embed"`
		}{"peer-invite/confirm", msgArg})
		if err != nil {
			req.CloseWithError(errors.Wrap(err, "failed to publish confirm message"))
			return
		}

		// legacy contact message
		// confirm should implicate alice<>bob are friends
		seq, err = h.pub.Append(struct {
			Type       string          `json:"type"`
			Contact    *ssb.FeedRef    `json:"contact"`
			Following  bool            `json:"following"`
			AutoFollow bool            `json:"auto"`
			Receipt    *ssb.MessageRef `json:"peerReceipt"`
		}{"contact", content.ID, true, true, content.Receipt})
		if err != nil {
			req.CloseWithError(errors.Wrap(err, "failed to publish confirm message"))
			return
		}

		req.Return(ctx, fmt.Sprint("confirmed as:", seq.Seq()))
	default:
		req.CloseWithError(fmt.Errorf("unknown method"))
	}

}

//  hash("peer-invites:DEVELOPMENT") //XXX DON'T publish without fixing this!
var peerCap = [32]byte{166, 106, 254, 35, 51, 62, 225, 80, 25, 130, 46, 71, 229, 179, 168, 165, 121, 48, 159, 58, 171, 54, 235, 44, 75, 176, 237, 0, 155, 31, 109, 253}

func verifyAcceptMessage(raw []byte, guestID *ssb.FeedRef) (*acceptContent, error) {
	var rawContent struct {
		Content json.RawMessage
	}
	err := json.Unmarshal(raw, &rawContent)
	if err != nil {
		return nil, errors.Wrap(err, "unwrap content for verify failed")
	}

	// fmt.Fprintln(os.Stderr, "msg:", string(rawContent.Content))

	// can verify the invite message
	enc, err := message.EncodePreserveOrder(rawContent.Content)
	if err != nil {
		return nil, err
	}
	invmsgWoSig, sig, err := message.ExtractSignature(enc)
	if err != nil {
		return nil, err
	}

	mac := auth.Sum(invmsgWoSig, &peerCap)
	err = sig.Verify(mac[:], guestID)
	if err != nil {
		return nil, err
	}

	var inviteAccept struct {
		Author  *ssb.FeedRef `json:"author"`
		Content acceptContent
	}

	if err := json.Unmarshal(raw, &inviteAccept); err != nil {
		return nil, errors.Wrap(err, "unwrap content for sanatize failed")
	}

	if inviteAccept.Content.Type != "peer-invite/accept" {
		return nil, errors.Errorf("invalid type on accept message")
	}

	if !bytes.Equal(inviteAccept.Author.ID, inviteAccept.Content.ID.ID) {
		return nil, errors.Errorf("invte is not for the right guest")
	}

	return &inviteAccept.Content, nil
}

type acceptContent struct {
	Type    string          `json:"type"`
	Receipt *ssb.MessageRef `json:"receipt"`
	ID      *ssb.FeedRef    `json:"id"`
	// Key     string          `json:"key"` only needed for reveal
}
