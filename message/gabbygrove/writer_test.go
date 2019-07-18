package gabbygrove_test

import (
	"bytes"
	"testing"

	proto "github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/gabbygrove"
)

func TestEncoder(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	dead := bytes.Repeat([]byte("dead"), 8)
	kp, err := ssb.NewKeyPair(bytes.NewReader(dead))
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoProto

	t.Log("kp:", kp.Id.Ref())

	// authorRef, err := gabbygrove.FromRef(kp.Id)
	// r.NoError(err)

	// cref := &ssb.BlobRef{
	// 	Hash: dead,
	// 	Algo: "ofc.sha256",
	// }
	// payloadRef, err := gabbygrove.FromRef(cref)
	// r.NoError(err)

	fakeRef, _ := gabbygrove.FromRef(&ssb.MessageRef{
		Hash: []byte("herberd"),
		Algo: ssb.RefAlgoSHA256,
	})

	var msgs = []interface{}{
		"foo.box",
		map[string]interface{}{
			"type": "test",
			"i":    1,
		},
		map[string]interface{}{
			"type":       "contact",
			"contact":    kp.Id.Ref(),
			"spectating": true,
		},
	}

	want := [][]byte{
		[]byte{0xa, 0x4c, 0x12, 0x21, 0x1, 0xae, 0xd3, 0xda, 0xb6, 0x5c, 0xe9, 0xe0, 0xd6, 0xc5, 0xd, 0x46, 0xfc, 0xef, 0xfb, 0x55, 0x22, 0x96, 0xed, 0x21, 0xb6, 0xe0, 0xb5, 0x37, 0xa6, 0xa0, 0x18, 0x45, 0x75, 0xce, 0x8f, 0x5c, 0xbd, 0x22, 0x27, 0x8, 0x1, 0x10, 0x7, 0x1a, 0x21, 0x3, 0xe8, 0x6, 0xec, 0xf2, 0xb7, 0xc3, 0x7f, 0xb0, 0x6d, 0xc1, 0x98, 0xa9, 0xb9, 0x5, 0xbe, 0x64, 0xee, 0x3f, 0xdb, 0x82, 0x37, 0xef, 0x80, 0xd3, 0x16, 0xac, 0xb7, 0xc8, 0x5b, 0xbf, 0x5f, 0x2, 0x12, 0x40, 0x6f, 0x88, 0x42, 0x8c, 0x80, 0x35, 0x2b, 0xde, 0x53, 0xfd, 0xce, 0x39, 0x5d, 0x70, 0x76, 0xe1, 0x21, 0x9e, 0x3c, 0x89, 0xcc, 0x8f, 0x59, 0xd4, 0xdd, 0xe3, 0x18, 0x53, 0xfe, 0xa7, 0xe5, 0xa4, 0xdf, 0xfc, 0x57, 0x79, 0xee, 0x28, 0x8f, 0x90, 0x67, 0x41, 0x30, 0x1e, 0x3d, 0x1c, 0xfc, 0x61, 0x65, 0x32, 0x58, 0x1e, 0xd8, 0x8d, 0x8d, 0x5f, 0xe2, 0xb8, 0xec, 0x1f, 0xc0, 0x87, 0xd0, 0x0, 0x1a, 0x7, 0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x6f, 0x78},

		[]byte{0xa, 0x4e, 0x12, 0x21, 0x1, 0xae, 0xd3, 0xda, 0xb6, 0x5c, 0xe9, 0xe0, 0xd6, 0xc5, 0xd, 0x46, 0xfc, 0xef, 0xfb, 0x55, 0x22, 0x96, 0xed, 0x21, 0xb6, 0xe0, 0xb5, 0x37, 0xa6, 0xa0, 0x18, 0x45, 0x75, 0xce, 0x8f, 0x5c, 0xbd, 0x18, 0x1, 0x22, 0x27, 0x8, 0x1, 0x10, 0x16, 0x1a, 0x21, 0x3, 0x95, 0xcc, 0xa4, 0xfa, 0x7b, 0x24, 0xab, 0xc6, 0x4, 0x96, 0x83, 0xe7, 0x16, 0x29, 0x2b, 0x0, 0xc4, 0x95, 0x9, 0xbe, 0x14, 0x7a, 0xa0, 0x24, 0xc0, 0x62, 0x86, 0xbd, 0x9b, 0x7d, 0xbd, 0xa8, 0x12, 0x40, 0x35, 0x1a, 0x53, 0xe7, 0x61, 0x89, 0xa8, 0x3d, 0x2e, 0x76, 0xd7, 0x56, 0x9, 0xe0, 0x97, 0x52, 0xb5, 0xac, 0x21, 0x61, 0x19, 0xc0, 0xe6, 0x7b, 0xa8, 0xca, 0x83, 0x4c, 0xf, 0x7c, 0x69, 0x5d, 0x85, 0xc, 0x4c, 0xa7, 0xd, 0xce, 0xd4, 0x42, 0x8b, 0x4e, 0xa9, 0x63, 0x53, 0x68, 0x48, 0xa2, 0xa6, 0xf1, 0x62, 0xfc, 0x71, 0xd6, 0xf, 0xb0, 0x4c, 0x52, 0xd5, 0x15, 0xf0, 0x63, 0xc6, 0x6, 0x1a, 0x16, 0x7b, 0x22, 0x69, 0x22, 0x3a, 0x31, 0x2c, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x22, 0x74, 0x65, 0x73, 0x74, 0x22, 0x7d, 0xa},

		[]byte{0xa, 0x71, 0xa, 0x21, 0x2, 0x68, 0x65, 0x72, 0x62, 0x65, 0x72, 0x64, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12, 0x21, 0x1, 0xae, 0xd3, 0xda, 0xb6, 0x5c, 0xe9, 0xe0, 0xd6, 0xc5, 0xd, 0x46, 0xfc, 0xef, 0xfb, 0x55, 0x22, 0x96, 0xed, 0x21, 0xb6, 0xe0, 0xb5, 0x37, 0xa6, 0xa0, 0x18, 0x45, 0x75, 0xce, 0x8f, 0x5c, 0xbd, 0x18, 0x2, 0x22, 0x27, 0x8, 0x1, 0x10, 0x65, 0x1a, 0x21, 0x3, 0xcb, 0xb, 0xd9, 0x39, 0xd9, 0x1a, 0xbd, 0x3, 0x23, 0x4, 0x42, 0x45, 0xa4, 0x76, 0xfd, 0xe1, 0xb1, 0x8a, 0x51, 0x88, 0xe, 0xc0, 0x65, 0x94, 0x4f, 0x3c, 0x3a, 0x2a, 0x20, 0x13, 0x1d, 0x5e, 0x12, 0x40, 0xcd, 0xec, 0x3c, 0xf1, 0x58, 0xe3, 0x4, 0xf, 0x87, 0x14, 0xfa, 0xd4, 0x45, 0x53, 0x2e, 0x13, 0x99, 0x90, 0x6f, 0x8d, 0xc1, 0xbe, 0xd3, 0xa, 0x5d, 0x57, 0x4b, 0xcb, 0x13, 0xa7, 0x65, 0x98, 0xd4, 0x43, 0xa8, 0xc2, 0x55, 0x50, 0xed, 0x56, 0xa, 0x9c, 0x8f, 0xe, 0xad, 0x37, 0x86, 0xf6, 0xc9, 0x80, 0xf5, 0xd0, 0x62, 0x93, 0x29, 0x81, 0x77, 0xe2, 0xfe, 0x52, 0xa, 0x25, 0x5b, 0xf, 0x1a, 0x65, 0x7b, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x22, 0x3a, 0x22, 0x40, 0x72, 0x74, 0x50, 0x61, 0x74, 0x6c, 0x7a, 0x70, 0x34, 0x4e, 0x62, 0x46, 0x44, 0x55, 0x62, 0x38, 0x37, 0x2f, 0x74, 0x56, 0x49, 0x70, 0x62, 0x74, 0x49, 0x62, 0x62, 0x67, 0x74, 0x54, 0x65, 0x6d, 0x6f, 0x42, 0x68, 0x46, 0x64, 0x63, 0x36, 0x50, 0x58, 0x4c, 0x30, 0x3d, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x2c, 0x22, 0x73, 0x70, 0x65, 0x63, 0x74, 0x61, 0x74, 0x69, 0x6e, 0x67, 0x22, 0x3a, 0x74, 0x72, 0x75, 0x65, 0x2c, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x63, 0x74, 0x22, 0x7d, 0xa},
	}

	for msgidx, msg := range msgs {

		e := gabbygrove.NewEncoder(kp)
		var prevRef *gabbygrove.BinaryRef
		if msgidx != 0 {
			prevRef = fakeRef
		}
		tr, msgRef, err := e.Encode(uint64(msgidx), prevRef, msg)
		r.NoError(err, "msg[%02d]Encode failed", msgidx)
		r.NotNil(msgRef)

		got, err := proto.Marshal(tr)
		r.NoError(err, "msg[%02d]Marshal failed", msgidx)

		a.Len(got, len(want[msgidx]), "msg[%02d] wrong msg length", msgidx)
		a.Equal(want[msgidx], got, "msg[%02d] compare failed", msgidx)

		var tr2 gabbygrove.Transfer
		err = proto.Unmarshal(got, &tr2)
		r.NoError(err, "msg[%02d] test decode failed", msgidx)
		t.Logf("msg[%02d] transfer decode of %d bytes", msgidx, len(got))
		// t.Log(spew.Sdump(tr))

		// metaB, err := proto.Marshal(tr.Message.Meta)
		// r.NoError(err, "msg[%02d] test meta encode failed", msgidx)
		// t.Log(base64.StdEncoding.EncodeToString(got))

		// d := gabbygrove.NewDecoder(bytes.NewReader(got))

		// v, err := d.Next(nil)
		// r.NoError(err)

		// t.Logf("msg[%02d] %d:\n%s", msgidx, i, spew.Sdump(v))

	}

}
