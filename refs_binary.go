package ssb

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
)

type BinaryRefType byte

// enum of BinaryRefTypes
const (
	BinaryRefUndefined BinaryRefType = iota
	BinaryRefFeedLegacy
	BinaryRefMessage
	BinaryRefBlob
	BinaryRefContent
	BinaryRefFeedGabby
)

// BinaryRef is used as an compact internal storage representation
type BinaryRef struct {
	fr *FeedRef
	mr *MessageRef
	br *BlobRef // payload/content ref
}

var _ Ref = (*BinaryRef)(nil)

// currently all references are 32bytes long
// one additonal byte for tagging the type
const binrefSize = 33

func (ref BinaryRef) valid() (BinaryRefType, error) {
	i := 0
	var t BinaryRefType = BinaryRefUndefined
	if ref.fr != nil {
		i++
		switch ref.fr.Algo {
		case RefAlgoProto:
			t = BinaryRefFeedGabby
		case RefAlgoEd25519:
			t = BinaryRefFeedLegacy
		default:
			return BinaryRefUndefined, ErrInvalidRef
		}
	}
	if ref.mr != nil {
		i++
		t = BinaryRefMessage
	}
	if ref.br != nil {
		i++
		t = BinaryRefBlob
	}
	if i > 1 {
		return BinaryRefUndefined, errors.Errorf("more than one ref in binref")
	}
	return t, nil
}

func (ref BinaryRef) Ref() string {
	t, err := ref.valid()
	if err != nil {
		panic(err)
	}
	r, err := ref.GetRef(t)
	if err != nil {
		panic(err)
	}
	return r.Ref()
}

func (ref BinaryRef) Marshal() ([]byte, error) {
	b := make([]byte, binrefSize)
	n, err := ref.MarshalTo(b)
	b = b[:n]
	return b, err
}

func (ref *BinaryRef) MarshalTo(data []byte) (n int, err error) {
	t, err := ref.valid()
	if err != nil {
		return 0, err
	}
	switch t {
	case BinaryRefFeedLegacy:
		copy(data, append([]byte{0x01}, ref.fr.ID...))
	case BinaryRefMessage:
		copy(data, append([]byte{0x02}, ref.mr.Hash...))
	case BinaryRefBlob:
		copy(data, append([]byte{0x03}, ref.br.Hash...))
	// case BinaryRefFeedGabby:
	// 	copy(data, append([]byte{0x05}, ref.fr.ID...))
	default:
		return 0, errors.Wrapf(ErrInvalidRefType, "invalid binref type: %x", t)
	}
	return binrefSize, nil
}

func (ref *BinaryRef) Unmarshal(data []byte) error {
	if n := len(data); n != binrefSize {
		return ErrRefLen{algo: "unknown", n: n}
	}
	switch data[0] {
	case 0x01:
		ref.fr = &FeedRef{
			ID:   data[1:],
			Algo: RefAlgoEd25519,
		}
	case 0x02:
		ref.mr = &MessageRef{
			Hash: data[1:],
			Algo: RefAlgoSHA256,
		}
	case 0x03:
		ref.br = &BlobRef{
			Hash: data[1:],
			Algo: RefAlgoSHA256,
		}
	default:
		return errors.Wrapf(ErrInvalidRefType, "invalid binref type: %x", data[0])
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
	if ref.br != nil {
		return bytestr(ref.br), nil
	}
	return nil, fmt.Errorf("should not all be nil")
}

func bytestr(r Ref) []byte {
	return []byte("\"" + r.Ref() + "\"")
}

func (ref *BinaryRef) UnmarshalJSON(data []byte) error {
	spew.Dump(ref)
	return errors.Errorf("TODO:json")
}

func (ref BinaryRef) GetRef(t BinaryRefType) (Ref, error) {
	hasT, err := ref.valid()
	if err != nil {
		return nil, errors.Wrap(err, "GetRef: invalid reference")
	}
	if hasT != t {
		return nil, errors.Errorf("GetRef: asked for type differs (has %d)", hasT)
	}
	// we could straight up return what is stored
	// but then we still have to assert afterwards if it really is what we want
	var ret Ref
	switch t {
	case BinaryRefFeedLegacy:
		ret = ref.fr
	case BinaryRefMessage:
		ret = ref.mr
	case BinaryRefBlob:
		ret = ref.br
	default:
		return nil, errors.Wrapf(ErrInvalidRefType, "invalid binref type: %x", t)
	}
	return ret, nil
}

func FromFeedRef(r *FeedRef) (*BinaryRef, error) {
	if ref := r.Ref(); len(ref) < 53 {
		return nil, errors.Errorf("what ref?")
	}
	return &BinaryRef{
		fr: r,
	}, nil
}

func FromRefString(s string) (*BinaryRef, error) {
	r, err := ParseRef(s)
	if err != nil {
		return nil, errors.Wrap(err, "binref: not a ssb ref")
	}
	return FromRef(r)
}

func FromRef(r Ref) (*BinaryRef, error) {
	var br BinaryRef
	switch tr := r.(type) {
	case *FeedRef:
		br.fr = tr
	case *MessageRef:
		br.mr = tr
	case *BlobRef:
		br.br = tr
	default:
		return nil, errors.Wrapf(ErrInvalidRefType, "invalid binref type: %T", r)
	}
	return &br, nil
}
