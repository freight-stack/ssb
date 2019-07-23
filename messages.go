package ssb

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"go.cryptoscope.co/margaret"
)

type Value struct {
	Previous  *MessageRef      `json:"previous"`
	Author    FeedRef          `json:"author"`
	Sequence  margaret.BaseSeq `json:"sequence"`
	Timestamp float64          `json:"timestamp"`
	Hash      string           `json:"hash"`
	Content   interface{}      `json:"content"`
	Signature string           `json:"signature"`
}

// Abstract allows accessing message aspects without known the feed type
// TODO: would prefer to strip the Get previs of these but it would conflict with legacy StoredMessage's fields
type Message interface {
	Key() *MessageRef
	Previous() *MessageRef

	margaret.Seq

	// TODO: received vs claimed
	Timestamp() time.Time
	//Time() time.Time?

	Author() *FeedRef
	ContentBytes() []byte

	ValueContent() *Value
	ValueContentJSON() json.RawMessage
}

// ValidateNext checks the author stays the same across the feed,
// that he previous hash is correct and that the sequence number is increasing correctly
// TODO: move all the message's publish and drains to it's own package
func ValidateNext(current, next Message) error {
	if current != nil {
		author := current.Author()

		if !author.Equal(next.Author()) {
			return errors.Errorf("ValidateNext(%s:%d): wrong author: %s", author.Ref(), current.Seq(), next.Author().Ref())
		}

		if bytes.Compare(current.Key().Hash, next.Previous().Hash) != 0 {
			return errors.Errorf("ValidateNext(%s:%d): previous compare failed expected:%s incoming:%s",
				author.Ref(),
				current.Seq(),
				current.Key().Ref(),
				next.Previous().Ref(),
			)
		}
		if current.Seq()+1 != next.Seq() {
			return errors.Errorf("ValidateNext(%s:%d): next.seq != curr.seq+1", author.Ref(), current.Seq())
		}

	} else { // first message
		if next.Seq() != 1 {
			return errors.Errorf("ValidateNext(%s:%d): first message has to have sequence 1", next.Author().Ref(), next.Seq())
		}
	}

	return nil
}

type Contact struct {
	Type      string   `json:"type"`
	Contact   *FeedRef `json:"contact"`
	Following bool     `json:"following"`
	Blocking  bool     `json:"blocking"`
}

func (c *Contact) UnmarshalJSON(b []byte) error {
	var priv string
	err := json.Unmarshal(b, &priv)
	if err == nil {
		return ErrWrongType{want: "contact", has: "private.box?"}
	}

	var potential map[string]interface{}
	err = json.Unmarshal(b, &potential)
	if err != nil {
		return errors.Wrap(err, "contact: map stage failed")
	}

	t, ok := potential["type"].(string)
	if !ok {
		return ErrMalfromedMsg{"contact: no type on message", nil}
	}

	if t != "contact" {
		return ErrWrongType{want: "contact", has: t}
	}

	newC := new(Contact)

	contact, ok := potential["contact"].(string)
	if !ok {
		return ErrMalfromedMsg{"contact: no string contact field on type:contact", potential}
	}

	newC.Contact, err = ParseFeedRef(contact)
	if err != nil {
		return errors.Wrap(err, "contact: map stage failed")
	}

	newC.Following, _ = potential["following"].(bool)
	newC.Blocking, _ = potential["blocking"].(bool)

	*c = *newC
	return nil
}

type About struct {
	About             *FeedRef
	Name, Description string
	Image             *BlobRef
}

func (a *About) UnmarshalJSON(b []byte) error {
	var priv string
	err := json.Unmarshal(b, &priv)
	if err == nil {
		return ErrWrongType{want: "about", has: "private.box?"}
	}

	var potential map[string]interface{}
	err = json.Unmarshal(b, &potential)
	if err != nil {
		return errors.Wrap(err, "about: map stage failed")
	}

	t, ok := potential["type"].(string)
	if !ok {
		return ErrMalfromedMsg{"about: no type on message", nil}
	}

	if t != "about" {
		return ErrWrongType{want: "about", has: t}
	}

	newA := new(About)

	about, ok := potential["about"].(string)
	if !ok {
		return ErrMalfromedMsg{"about: no string about field on type:about", potential}
	}

	newA.About, err = ParseFeedRef(about)
	if err != nil {
		return errors.Wrap(err, "about: who?")
	}

	if newName, ok := potential["name"].(string); ok {
		newA.Name = newName
	}
	if newDesc, ok := potential["description"].(string); ok {
		newA.Description = newDesc
	}

	var newImgBlob string
	if img, ok := potential["image"].(string); ok {
		newImgBlob = img
	}
	if imgObj, ok := potential["image"].(map[string]interface{}); ok {
		lnk, ok := imgObj["link"].(string)
		if ok {
			newImgBlob = lnk
		}
	}
	if newImgBlob != "" {
		br, err := ParseBlobRef(newImgBlob)
		if err != nil {
			return errors.Wrapf(err, "about: invalid image: %q", newImgBlob)
		}
		newA.Image = br
	}

	*a = *newA
	return nil
}
