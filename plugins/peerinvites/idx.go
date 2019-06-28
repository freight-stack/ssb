package peerinvites

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.cryptoscope.co/luigi"
	"golang.org/x/crypto/nacl/auth"

	"go.cryptoscope.co/librarian"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/multilog"

	"github.com/cryptix/go/logging"
	"github.com/pkg/errors"
	"go.cryptoscope.co/muxrpc"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message"
	"go.cryptoscope.co/ssb/plugins/get"
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

func (p *Plugin) getAllInvites() {
	invMsgLog, err := p.tl.Get(librarian.Addr("peer-invite"))
	if err != nil {
		p.logger.Log("processingErr", "failed to get typed sublog", "err", err)
		return
	}
	// live is borked?!
	src, err := invMsgLog.Query()
	if err != nil {
		p.logger.Log("processingErr", "failed to construct query", "err", err)
		return
	}

	err = luigi.Pump(context.Background(), luigi.FuncSink(p.addInvite), src)
	if err != nil {
		p.logger.Log("processingErr", "failed to pump messages", "err", err)
		return
	}
}

func (p *Plugin) addInvite(_ context.Context, v interface{}, err error) error {
	if err != nil {
		return err
	}
	storedMsgSeq, ok := v.(margaret.BaseSeq)
	if !ok {
		return fmt.Errorf("unexpeced stored message type: %T", v)
	}
	// assume dist check is okay

	storedV, err := p.rl.Get(storedMsgSeq)
	if err != nil {
		return err
	}

	storedMsg, ok := storedV.(message.StoredMessage)
	if !ok {
		return fmt.Errorf("unexpeced stored message type: %T", storedV)
	}

	var invCore struct {
		Content struct {
			Invite *ssb.FeedRef `json:"invite"`
			Host   *ssb.FeedRef `json:"host"`
		} `json:"content"`
	}
	err = json.Unmarshal(storedMsg.Raw, &invCore)
	if err != nil {
		return err
	}

	if invCore.Content.Invite == nil {
		return fmt.Errorf("invalid invite")
	}
	guestRef := invCore.Content.Invite.Ref()
	p.h.pendingL.Lock()
	defer p.h.pendingL.Unlock()
	valid, has := p.h.pending[guestRef]
	if has && !valid { // dont re-add spent invites
		return nil
	}
	p.h.pending[guestRef] = true
	// p.logger.Log("msg", "got invite", "author", storedMsg.Author.Ref(), "guest", guestRef)
	p.logger.Log("activeinvites", len(p.h.pending))
	return nil
}

func (p *Plugin) getAllConfirmed() {
	invMsgLog, err := p.tl.Get(librarian.Addr("peer-invite/confirm"))
	if err != nil {
		p.logger.Log("processingErr", "failed to get typed sublog", "err", err)
		return
	}
	// live is borked?!
	src, err := invMsgLog.Query()
	if err != nil {
		p.logger.Log("processingErr", "failed to construct query", "err", err)
		return
	}

	err = luigi.Pump(context.Background(), luigi.FuncSink(p.blockUsed), src)
	if err != nil {
		p.logger.Log("processingErr", "failed to pump messages", "err", err)
		return
	}
}

func (p *Plugin) blockUsed(_ context.Context, v interface{}, err error) error {
	if err != nil {
		return err
	}
	storedMsgSeq, ok := v.(margaret.BaseSeq)
	if !ok {
		return fmt.Errorf("unexpeced stored message type: %T", v)
	}

	storedV, err := p.rl.Get(storedMsgSeq)
	if err != nil {
		return err
	}

	storedMsg, ok := storedV.(message.StoredMessage)
	if !ok {
		return fmt.Errorf("unexpeced stored message type: %T", storedV)
	}

	var invConfirm struct {
		Content struct {
			Embed struct {
				Content acceptContent `json:"content"`
			} `json:"embed"`
		} `json:"content"`
	}
	err = json.Unmarshal(storedMsg.Raw, &invConfirm)
	if err != nil {
		return err
	}
	accptMsg := invConfirm.Content.Embed.Content

	if accptMsg.Receipt == nil {
		return fmt.Errorf("invalid recipt on confirm msg")
	}

	msg, err := p.h.g.Get(*accptMsg.Receipt)
	if err != nil {
		return err
	}

	var invCore struct {
		Content struct {
			Invite *ssb.FeedRef `json:"invite"`
			Host   *ssb.FeedRef `json:"host"`
		} `json:"content"`
	}
	err = json.Unmarshal(msg.Raw, &invCore)
	if err != nil {
		return err
	}

	p.h.pendingL.Lock()
	defer p.h.pendingL.Unlock()
	p.h.pending[invCore.Content.Invite.Ref()] = false
	return nil

}

func (p *Plugin) Authorize(to *ssb.FeedRef) error {
	p.h.pendingL.Lock()
	defer p.h.pendingL.Unlock()
	if p.h.pending[to.Ref()] {
		p.logger.Log("authorized", "auth", "to", to.Ref())
		return nil
	}
	return errors.New("not for us")
}

var (
	_ ssb.Plugin     = (*Plugin)(nil)
	_ ssb.Authorizer = (*Plugin)(nil)
)

func New(logger logging.Interface, g get.Getter, typeLog multilog.MultiLog, rootLog, publishLog margaret.Log) Plugin {

	p := Plugin{
		logger: logger,

		tl: typeLog,
		rl: rootLog,

		h: handler{
			pending: make(map[string]bool),

			g:   g,
			tl:  typeLog,
			rl:  rootLog,
			pub: publishLog,
		},
	}

	go func() {
		for { // TODO: get live query working or make own idx
			p.getAllConfirmed()
			p.getAllInvites()

			time.Sleep(1 * time.Second)
		}
	}()
	return p
}

type handler struct {
	pendingL sync.Mutex
	pending  map[string]bool

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

		h.pendingL.Lock()
		defer h.pendingL.Unlock()
		h.pending[guestRef.Ref()] = false

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
