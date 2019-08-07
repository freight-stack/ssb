package multimsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/margaret"
	"go.mindeco.de/ssb-gabbygrove"
	"go.mindeco.de/ssb-protochain"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/legacy"
)

func TestMultiMsgLegacy(t *testing.T) {
	r := require.New(t)

	kpSeed := bytes.Repeat([]byte("feed"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(kpSeed))
	r.NoError(err)

	// craft legacy testmessage
	testContent := []byte(`{Hello: world}`)
	var lm legacy.StoredMessage
	lm.Author_ = kp.Id
	lm.Sequence_ = 123
	lm.Raw_ = testContent

	var mm MultiMessage
	mm.tipe = Legacy
	mm.Message = &lm

	b, err := mm.MarshalBinary()
	r.NoError(err)
	r.Equal(Legacy, MessageType(b[0]))

	var mm2 MultiMessage
	err = mm2.UnmarshalBinary(b)
	r.NoError(err)
	r.NotNil(mm2.Message)
	r.Equal(Legacy, mm2.tipe)
	legacy, ok := mm2.AsLegacy()
	r.True(ok)
	r.Equal(testContent, legacy.Raw_)
	r.Equal(margaret.BaseSeq(123).Seq(), legacy.Seq())
}

func TestMultiMsgProto(t *testing.T) {
	r := require.New(t)

	kpSeed := bytes.Repeat([]byte("deaf"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(kpSeed))
	r.NoError(err)

	authorRef, err := protochain.NewBinaryRef(kp.Id)
	r.NoError(err)

	cref := &ssb.ContentRef{
		Hash: kpSeed,
		Algo: ssb.RefAlgoContentProto,
	}
	payloadRef, err := protochain.NewBinaryRef(cref)
	r.NoError(err)

	now1 := uint64(time.Unix(631249445, 0).Unix())
	var evt = &protochain.Event{
		Author:   authorRef,
		Sequence: 123,
		Content: &protochain.Event_Content{
			Hash:  payloadRef,
			Size_: 23,
			Type:  protochain.ContentType_JSON,
		},
		Timestamp: now1,
	}

	evtBytes, err := proto.Marshal(evt)
	r.NoError(err)

	testContent := []byte("someContent")
	tr := &protochain.Transfer{
		Event:     evtBytes,
		Signature: []byte("none"),
		Content:   testContent,
	}

	var mm MultiMessage
	mm.tipe = Proto
	mm.Message = tr

	b, err := mm.MarshalBinary()
	r.NoError(err)
	r.Equal(Proto, MessageType(b[0]))

	var mm2 MultiMessage
	err = mm2.UnmarshalBinary(b)
	r.NoError(err)
	proto, ok := mm2.AsProto()
	r.True(ok)
	r.Equal(Proto, mm2.tipe)
	r.Equal(testContent, proto.Content)
	r.Equal([]byte("none"), proto.Signature)
	evt2, err := proto.UnmarshaledEvent()
	r.NoError(err)
	r.Equal(uint64(123), evt2.Sequence)
}
func TestMultiMsgGabby(t *testing.T) {
	r := require.New(t)

	kpSeed := bytes.Repeat([]byte("bee4"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(kpSeed))
	r.NoError(err)

	authorRef, err := gabbygrove.NewBinaryRef(kp.Id)
	r.NoError(err)

	cref := &ssb.ContentRef{
		Hash: kpSeed,
		Algo: ssb.RefAlgoContentGabby,
	}
	payloadRef, err := gabbygrove.NewBinaryRef(cref)
	r.NoError(err)

	var evt = &gabbygrove.Event{
		Author:   authorRef,
		Sequence: 123,
		Content: gabbygrove.Content{
			Hash: payloadRef,
			Size: 23,
			Type: gabbygrove.ContentTypeJSON,
		},
	}

	evtBytes, err := evt.MarshalCBOR()
	r.NoError(err)

	testContent := []byte("someContent")
	tr := &gabbygrove.Transfer{
		Event:     evtBytes,
		Signature: []byte("none"),
		Content:   testContent,
	}

	var mm MultiMessage
	mm.tipe = Gabby
	mm.Message = tr

	b, err := mm.MarshalBinary()
	r.NoError(err)
	r.Equal(Gabby, MessageType(b[0]))

	var mm2 MultiMessage
	err = mm2.UnmarshalBinary(b)
	r.NoError(err)
	r.Equal(Gabby, mm.tipe)
	gabby, ok := mm2.AsGabby()
	r.True(ok)
	r.NotNil(gabby)
	r.Equal(testContent, gabby.Content)
	r.Equal([]byte("none"), gabby.Signature)
	evt2, err := gabby.UnmarshaledEvent()
	r.NoError(err)
	r.Equal(uint64(123), evt2.Sequence)
}
