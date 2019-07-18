package gabbygrove

import (
	"encoding/json"

	"github.com/golang/protobuf/proto"
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
	pubKey := evt.Author.fr.ID
	return ed25519.Verify(pubKey, tr.Event, tr.Signature)
}

func (tr *Transfer) UnmarshaledEvent() (*Event, error) {
	return tr.getEvent()
}

func (tr *Transfer) getEvent() (*Event, error) {
	var evt Event
	err := proto.Unmarshal(tr.Event, &evt)
	if err != nil {
		return nil, err
	}
	return &evt, nil
}

func (tr *Transfer) Seq() int64 {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}

	return int64(evt.Sequence)
}

// func (tr Transfer) Previous() *ssb.MessageRef {
// 	return tr.Previous
// }

func (tr Transfer) ValueContent() *ssb.Value {
	evt, err := tr.getEvent()
	if err != nil {
		panic(err)
	}
	var msg ssb.Value
	if evt.Previous != nil {
		msg.Previous = evt.Previous.mr
	}
	msg.Author = *evt.Author.fr
	msg.Sequence = margaret.BaseSeq(evt.Sequence)
	msg.Hash = "sha256"
	// msg.Timestamp = float64(sm.Timestamp.Unix() * 1000)
	msg.Content = tr.GetContent()
	return &msg
}

func (tr Transfer) ValueContentJSON() json.RawMessage {
	jsonB, err := json.Marshal(tr.ValueContent())
	if err != nil {
		panic(err.Error())
	}

	return jsonB
}
