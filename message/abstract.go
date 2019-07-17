package message

import (
	"encoding/json"
	"log"

	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
)

// Abstract allows accessing message aspects without known the feed type
// TODO: would prefer to strip the Get previs of these but it would conflict with legacy StoredMessage's fields
type Abstract interface {
	GetKey() *ssb.MessageRef
	// GetPrevious() *ssb.MessageRef
	GetSequence() margaret.Seq
	// GetTimestamp() time.Time?
	GetAuthor() *ssb.FeedRef
	GetContent() []byte

	ValueContent() *Value
	ValueContentJSON() json.RawMessage
}

var _ Abstract = (*StoredMessage)(nil)

func (sm StoredMessage) GetSequence() margaret.Seq {
	return sm.Sequence
}

func (sm StoredMessage) GetKey() *ssb.MessageRef {
	return sm.Key
}

func (sm StoredMessage) GetAuthor() *ssb.FeedRef {
	return sm.Author
}

func (sm StoredMessage) GetContent() []byte {
	var c struct {
		Content json.RawMessage `json:"content"`
	}
	err := json.Unmarshal(sm.Raw, &c)
	if err != nil {
		log.Println("warning: getContent of storedMessage failed:", err)
		return nil
	}
	return c.Content
}

func (sm StoredMessage) ValueContent() *Value {
	var msg Value
	msg.Previous = sm.Previous
	msg.Author = *sm.Author
	msg.Sequence = sm.Sequence
	msg.Hash = "sha256"
	// msg.Timestamp = float64(sm.Timestamp.Unix() * 1000)
	var cs struct {
		Content   json.RawMessage `json:"content"`
		Signature string          `json:"signature"`
	}
	err := json.Unmarshal(sm.Raw, &cs)
	if err != nil {
		log.Println("warning: getContent of storedMessage failed:", err)
		return nil
	}
	msg.Content = cs.Content
	msg.Signature = cs.Signature
	return &msg
}

func (sm StoredMessage) ValueContentJSON() json.RawMessage {
	// jsonB, err := json.Marshal(sm.ValueContent())
	// if err != nil {
	// 	panic(err.Error())
	// }

	return sm.Raw
}
