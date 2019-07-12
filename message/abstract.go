package message

import (
	"encoding/json"
	"log"

	"go.cryptoscope.co/ssb"
)

// Abstract allows accessing message aspects without known the feed type
// TODO: would prefer to strip the Get previs of these but it would conflict with legacy StoredMessage's fields
type Abstract interface {
	// GetPrevious() *ssb.MessageRef
	// GetSequence() margaret.Seq
	// GetTimestamp() time.Time?
	GetAuthor() *ssb.FeedRef
	GetContent() []byte
}

var _ Abstract = (*StoredMessage)(nil)

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
