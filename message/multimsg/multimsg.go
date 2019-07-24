package multimsg

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	fmt "fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/gabbygrove"
	"go.cryptoscope.co/ssb/message/legacy"
	"go.cryptoscope.co/ssb/message/protochain"
)

type MessageType byte

const (
	Unknown MessageType = iota
	Legacy
	Proto
	Gabby
)

// MultiMessage attempts to support multiple message formats in the same storage layer
// currently supports Proto and legacy
type MultiMessage struct {
	tipe   MessageType
	key    *ssb.MessageRef
	proto  *protochain.Transfer
	legacy *legacy.StoredMessage
	gabby  *gabbygrove.Transfer
}

func (mm MultiMessage) MarshalBinary() ([]byte, error) {
	switch mm.tipe {
	case Legacy:
		var buf bytes.Buffer
		buf.Write([]byte{byte(Legacy)})

		var mh codec.MsgpackHandle
		enc := codec.NewEncoder(&buf, &mh)
		err := enc.Encode(mm.legacy)
		if err != nil {
			return nil, errors.Wrap(err, "multiMessage: legacy encoding failed")
		}
		return buf.Bytes(), nil
	case Proto:
		trBytes, err := mm.proto.Marshal()
		if err != nil {
			return nil, errors.Wrap(err, "multiMessage: proto encoding failed")
		}
		return append([]byte{byte(Proto)}, trBytes...), nil
	case Gabby:
		var buf bytes.Buffer
		buf.Write([]byte{byte(Gabby)})
		err := gob.NewEncoder(&buf).Encode(mm.gabby)
		return buf.Bytes(), errors.Wrap(err, "multiMessage: gabby encoding failed")
	}
	return nil, errors.Errorf("multiMessage: unsupported message type: %x", mm.tipe)
}

func (mm *MultiMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return errors.Errorf("multiMessage: data to short")
	}

	mm.tipe = MessageType(data[0])
	switch mm.tipe {
	case Legacy:
		var msg legacy.StoredMessage
		var mh codec.MsgpackHandle
		dec := codec.NewDecoderBytes(data[1:], &mh)
		err := dec.Decode(&msg)
		if err != nil {
			return errors.Wrap(err, "multiMessage: legacy decoding failed")
		}
		mm.legacy = &msg
		mm.key = msg.Key_
	case Proto:
		var tr protochain.Transfer
		err := tr.Unmarshal(data[1:])
		if err != nil {
			return errors.Wrap(err, "multiMessage: proto decoding failed")
		}
		mm.proto = &tr
		mm.key = tr.Key()
	case Gabby:
		rd := bytes.NewReader(data[1:])
		var gb gabbygrove.Transfer
		err := gob.NewDecoder(rd).Decode(&gb)
		if err != nil {
			return errors.Wrap(err, "multiMessage: gabby decoding failed")
		}
		mm.gabby = &gb
		mm.key = gb.Key()
	default:
		return errors.Errorf("multiMessage: unsupported message type: %x", mm.tipe)
	}
	return nil
}

// TODO: replace with AsLegacy() and AsProto()
func (mm MultiMessage) AsLegacy() (*legacy.StoredMessage, bool) {
	if mm.tipe != Legacy {
		return nil, false
	}
	return mm.legacy, true
}

func (mm MultiMessage) AsProto() (*protochain.Transfer, bool) {
	if mm.tipe != Proto {
		return nil, false
	}
	return mm.proto, true
}

func (mm MultiMessage) AsGabby() (*gabbygrove.Transfer, bool) {
	if mm.tipe != Gabby {
		return nil, false
	}
	return mm.gabby, true
}

var _ ssb.Message = (*MultiMessage)(nil)

func (mm MultiMessage) Author() *ssb.FeedRef {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Author()
	case Proto:
		return mm.proto.Author()
	case Gabby:
		return mm.gabby.Author()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) Previous() *ssb.MessageRef {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Previous()
	case Proto:
		return mm.proto.Previous()
	case Gabby:
		return mm.gabby.Previous()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) Timestamp() time.Time {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Timestamp()
	case Proto:
		return mm.proto.Timestamp()
	case Gabby:
		return mm.gabby.Timestamp()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) ContentBytes() []byte {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.ContentBytes()
	case Proto:
		return mm.proto.ContentBytes()
	case Gabby:
		return mm.gabby.ContentBytes()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) Key() *ssb.MessageRef {
	return mm.key
}

func (mm MultiMessage) Seq() int64 {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Seq()
	case Proto:
		return mm.proto.Seq()
	case Gabby:
		return mm.gabby.Seq()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) ValueContent() *ssb.Value {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.ValueContent()
	case Proto:
		return mm.proto.ValueContent()
	case Gabby:
		return mm.gabby.ValueContent()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) ValueContentJSON() json.RawMessage {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.ValueContentJSON()
	case Proto:
		return mm.proto.ValueContentJSON()
	case Gabby:
		return mm.gabby.ValueContentJSON()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func NewMultiMessageFromLegacy(msg *legacy.StoredMessage) *MultiMessage {
	var mm MultiMessage
	mm.tipe = Legacy
	mm.key = msg.Key_
	mm.legacy = msg
	return &mm
}
