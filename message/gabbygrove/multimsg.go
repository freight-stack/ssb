package gabbygrove

import (
	"bytes"
	"encoding/json"
	fmt "fmt"
	"runtime/debug"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/legacy"
)

type MessageType byte

const (
	Unknown MessageType = iota
	Legacy
	Proto
)

// MultiMessage attempts to support multiple message formats in the same storage layer
// currently supports Proto and legacy
type MultiMessage struct {
	tipe   MessageType
	key    *ssb.MessageRef
	proto  *Transfer
	legacy *legacy.StoredMessage
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
		trBytes, err := proto.Marshal(mm.proto)
		if err != nil {
			return nil, errors.Wrap(err, "multiMessage: proto encoding failed")
		}

		// for js test:
		// fmt.Printf("tr: %x\n", trBytes)

		return append([]byte{byte(Proto)}, trBytes...), nil
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
		var tr Transfer
		err := proto.Unmarshal(data[1:], &tr)
		if err != nil {
			return errors.Wrap(err, "multiMessage: proto decoding failed")
		}
		mm.proto = &tr
		mm.key = tr.Key()
	default:
		return errors.Errorf("multiMessage: unsupported message type: %x", mm.tipe)
	}
	return nil
}

// TODO: replace with AsLegacy() and AsProto()
func (mm MultiMessage) ByType(mt MessageType) (interface{}, error) {
	if mt != mm.tipe {
		debug.PrintStack()
		return nil, errors.Errorf("multiMessage: wrong message type - has: %x", mm.tipe)
	}
	switch mm.tipe {
	case Legacy:
		return mm.legacy, nil
	case Proto:
		return mm.proto, nil
	}
	return nil, errors.Errorf("multiMessage: unsupported message type: %x", mm.tipe)
}

var _ ssb.Message = (*MultiMessage)(nil)

func (mm MultiMessage) Author() *ssb.FeedRef {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Author()
	case Proto:
		evt, err := mm.proto.getEvent()
		if err != nil {
			return nil
		}
		return evt.Author.fr
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) Previous() *ssb.MessageRef {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Previous()
	case Proto:
		evt, err := mm.proto.getEvent()
		if err != nil {
			return nil
		}
		return evt.Previous.mr
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) Timestamp() time.Time {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Timestamp()
	case Proto:
		evt, err := mm.proto.getEvent()
		if err != nil {
			panic(err)
		}
		return time.Unix(int64(evt.Timestamp), 0)
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) Content() []byte {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.Content()
	case Proto:
		return mm.proto.Content
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
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) ValueContent() *ssb.Value {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.ValueContent()
	case Proto:
		return mm.proto.ValueContent()
	}
	panic(fmt.Sprintf("multiMessage: unsupported message type: %x", mm.tipe))
}

func (mm MultiMessage) ValueContentJSON() json.RawMessage {
	switch mm.tipe {
	case Legacy:
		return mm.legacy.ValueContentJSON()
	case Proto:
		return mm.proto.ValueContentJSON()
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
