package protochain

import (
	"encoding/json"
	"time"

	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
	"golang.org/x/crypto/ed25519"
)

// Verify returns true if the Message was signed by the author specified by the meta portion of the message
func (tr *Transfer) Verify() bool {
	evt, err := tr.getEvent()
	if err != nil {
		return false
	}
	aref, err := evt.Author.GetRef(RefType_FeedRef)
	if err != nil {
		panic(err)
	}

	pubKey := aref.(*ssb.FeedRef).ID
	return ed25519.Verify(pubKey, tr.Event, tr.Signature)
}

func (tr *Transfer) UnmarshaledEvent() (*Event, error) {
	return tr.getEvent()
}

func (tr *Transfer) getEvent() (*Event, error) {
	if tr.lazyEvent != nil {
		return tr.lazyEvent, nil
	}
	var evt Event
	err := evt.Unmarshal(tr.Event)
	if err != nil {
		return nil, err
	}
	tr.lazyEvent = &evt
	return &evt, nil
}

var _ ssb.Message = (*Transfer)(nil)

func (tr *Transfer) Seq() int64 {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}

	return int64(evt.Sequence)
}

func (tr *Transfer) Author() *ssb.FeedRef {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	aref, err := evt.Author.GetRef(RefType_FeedRef)
	if err != nil {
		panic(err)
	}
	return aref.(*ssb.FeedRef)
}

func (tr *Transfer) Previous() *ssb.MessageRef {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	if evt.Previous == nil && evt.Sequence == 1 {
		return nil
	}
	mref, err := evt.Previous.GetRef(RefType_MessageRef)
	if err != nil {
		panic(err)
	}
	return mref.(*ssb.MessageRef)
}

func (tr *Transfer) Timestamp() time.Time {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	return time.Unix(int64(evt.Timestamp), 0)
}

func (tr *Transfer) ContentBytes() []byte {
	return tr.Content
}

func (tr *Transfer) ValueContent() *ssb.Value {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	var msg ssb.Value
	if evt.Previous != nil {
		ref, err := evt.Previous.GetRef(RefType_MessageRef)
		if err != nil {
			panic(err)
		}
		msg.Previous = ref.(*ssb.MessageRef)
	}
	aref, err := evt.Author.GetRef(RefType_FeedRef)
	if err != nil {
		panic(err)
	}
	msg.Author = *aref.(*ssb.FeedRef)
	msg.Sequence = margaret.BaseSeq(evt.Sequence)
	msg.Hash = "sha256"
	// msg.Timestamp = float64(sm.Timestamp.Unix() * 1000)
	msg.Content = tr.GetContent()
	return &msg
}

func (tr *Transfer) ValueContentJSON() json.RawMessage {
	jsonB, err := json.Marshal(tr.ValueContent())
	if err != nil {
		panic(err.Error())
	}

	return jsonB
}
