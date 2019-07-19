package message

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
)

func TestMultiMsgLegacy(t *testing.T) {
	r := require.New(t)

	dead := bytes.Repeat([]byte("feed"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
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

	dead := bytes.Repeat([]byte("deaf"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)

	authorRef, err := ssb.FromRef(kp.Id)
	r.NoError(err)

	cref := &ssb.BlobRef{
		Hash: dead,
		Algo: "ofc.sha256",
	}
	payloadRef, err := ssb.FromRef(cref)
	r.NoError(err)

	now1 := uint64(time.Unix(631249445, 0).Unix())
	var evt = &gabbygrove.Event{
		Author:   authorRef,
		Sequence: 123,
		Content: &gabbygrove.Event_Content{
			Hash:  payloadRef,
			Size_: 23,
			Type:  gabbygrove.ContentType_JSON,
		},
		Timestamp: now1,
	}

	evtBytes, err := proto.Marshal(evt)
	r.NoError(err)

	testContent := []byte("someContent")
	tr := &gabbygrove.Transfer{
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
