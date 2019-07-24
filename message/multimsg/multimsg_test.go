package multimsg

import (
	"bytes"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/gabbygrove"
	"go.cryptoscope.co/ssb/message/legacy"
	"go.cryptoscope.co/ssb/message/protochain"
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
	mm.legacy = &lm

	b, err := mm.MarshalBinary()
	r.NoError(err)
	r.Equal(Legacy, MessageType(b[0]))

	var mm2 MultiMessage
	err = mm2.UnmarshalBinary(b)
	r.NoError(err)
	r.Nil(mm2.proto)
	r.NotNil(mm2.legacy)
	r.Equal(Legacy, mm2.tipe)
	r.Equal(testContent, mm2.legacy.Raw_)
	r.Equal(margaret.BaseSeq(123).Seq(), mm2.legacy.Seq())
}

func TestMultiMsgProto(t *testing.T) {
	r := require.New(t)

	kpSeed := bytes.Repeat([]byte("deaf"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(kpSeed))
	r.NoError(err)

	authorRef, err := protochain.NewBinaryRef(kp.Id)
	r.NoError(err)

	cref := &ssb.BlobRef{
		Hash: kpSeed,
		Algo: "ofc.sha256",
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
	mm.proto = tr

	b, err := mm.MarshalBinary()
	r.NoError(err)
	r.Equal(Proto, MessageType(b[0]))

	var mm2 MultiMessage
	err = mm2.UnmarshalBinary(b)
	r.NoError(err)
	r.NotNil(mm2.proto)
	r.Nil(mm2.legacy)
	r.Equal(Proto, mm2.tipe)
	r.Equal(testContent, mm2.proto.Content)
	r.Equal([]byte("none"), mm2.proto.Signature)
	evt2, err := mm2.proto.UnmarshaledEvent()
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

	cref := &ssb.BlobRef{
		Hash: kpSeed,
		Algo: "ofc.sha256",
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
	mm.gabby = tr

	b, err := mm.MarshalBinary()
	r.NoError(err)
	r.Equal(Gabby, MessageType(b[0]))

	var mm2 MultiMessage
	err = mm2.UnmarshalBinary(b)
	r.NoError(err)
	r.Nil(mm2.proto)
	r.Nil(mm2.legacy)
	r.NotNil(mm2.gabby)
	r.Equal(Gabby, mm2.tipe)
	r.Equal(testContent, mm2.gabby.Content)
	r.Equal([]byte("none"), mm2.gabby.Signature)
	evt2, err := mm2.gabby.UnmarshaledEvent()
	r.NoError(err)
	r.Equal(uint64(123), evt2.Sequence)
}
