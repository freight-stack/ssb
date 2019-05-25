package protochain

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"go.cryptoscope.co/ssb"
)

// BinaryRef defines a binary representation for feed, message, and content references
type BinaryRef struct {
	fr *ssb.FeedRef
	mr *ssb.MessageRef
	cr *ssb.BlobRef // payload/content ref
}

// currently all references are 32bytes long
// one additonal byte for tagging the type
const binrefSize = 33

func (ref BinaryRef) valid() (RefType, error) {
	i := 0
	var t RefType = RefType_Undefined
	if ref.fr != nil {
		i++
		t = RefType_FeedRef
	}
	if ref.mr != nil {
		i++
		t = RefType_MessageRef
	}
	if ref.cr != nil {
		i++
		t = RefType_ContentRef
	}
	if i > 1 {
		return -1, fmt.Errorf("more than one ref in binref")
	}
	return t, nil
}

func (ref BinaryRef) Marshal() ([]byte, error) {
	var b []byte
	_, err := ref.MarshalTo(b)
	return b, err
}

func (ref *BinaryRef) MarshalTo(data []byte) (n int, err error) {
	t, err := ref.valid()
	if err != nil {
		return 0, err
	}
	switch t {
	case RefType_FeedRef:
		copy(data, append([]byte{0x01}, ref.fr.ID...))
	case RefType_MessageRef:
		copy(data, append([]byte{0x02}, ref.mr.Hash...))
	case RefType_ContentRef:
		copy(data, append([]byte{0x03}, ref.cr.Hash...))
	default:
		return 0, fmt.Errorf("invalid ref type: %d", t)
	}
	return binrefSize, nil
}

func (ref *BinaryRef) Unmarshal(data []byte) error {
	if n := len(data); n != binrefSize {
		return errors.Errorf("binref: invalid len:%d", n)
	}
	switch data[0] {
	case 0x01:
		ref.fr = &ssb.FeedRef{
			ID:   data[1:],
			Algo: ssb.RefAlgoProto,
		}
	case 0x02:
		ref.mr = &ssb.MessageRef{
			Hash: data[1:],
			Algo: ssb.RefAlgoSHA256,
		}
	case 0x03:
		ref.cr = &ssb.BlobRef{
			Hash: data[1:],
			Algo: "ofcmsg",
		}
	default:
		return fmt.Errorf("invalid binref type: %x", data[0])
	}
	return nil
}

func (ref *BinaryRef) Size() int {
	return binrefSize
}

func (ref BinaryRef) MarshalJSON() ([]byte, error) {
	if ref.fr != nil {
		return bytestr(ref.fr), nil
	}
	if ref.mr != nil {
		return bytestr(ref.mr), nil
	}
	if ref.cr != nil {
		return bytestr(ref.cr), nil
	}
	return nil, fmt.Errorf("should not all be nil")
}

func bytestr(r ssb.Ref) []byte {
	return []byte("\"" + r.Ref() + "\"")
}

func (ref *BinaryRef) UnmarshalJSON(data []byte) error {
	spew.Dump(ref)
	return errors.Errorf("TODO:json")
}

func (ref BinaryRef) GetRef(t RefType) (ssb.Ref, error) {
	hasT, err := ref.valid()
	if err != nil {
		return nil, errors.Wrap(err, "GetRef: invalid reference")
	}
	if hasT != t {
		return nil, errors.Errorf("GetRef: asked for type differs (has %d)", hasT)
	}
	// we could straight up return what is stored
	// but then we still have to assert afterwards if it really is what we want
	var ret ssb.Ref
	switch t {
	case RefType_FeedRef:
		ret = ref.fr
	case RefType_MessageRef:
		ret = ref.mr
	case RefType_ContentRef:
		ret = ref.cr
	default:
		return nil, fmt.Errorf("invalid ref type: %d", t)
	}
	return ret, nil
}

func NewBinaryRef(r ssb.Ref) (*BinaryRef, error) {
	return fromRef(r)
}

func fromRef(r ssb.Ref) (*BinaryRef, error) {
	var br BinaryRef
	switch tr := r.(type) {
	case *ssb.FeedRef:
		br.fr = tr
	case *ssb.MessageRef:
		br.mr = tr
	case *ssb.BlobRef: // content/payload ref
		br.cr = tr
	default:
		return nil, fmt.Errorf("invalid ref type: %T", r)
	}
	return &br, nil
}
