package ssb

import (
	"fmt"

	"github.com/pkg/errors"
)

type StorageRefType byte

// enum of StorageRefTypes
const (
	StorageRefUndefined StorageRefType = iota
	StorageRefFeedLegacy
	StorageRefMessage
	StorageRefBlob
	StorageRefContent
	StorageRefFeedProto
	StorageRefFeedGabby
)

// StorageRef is used as an compact internal storage representation
type StorageRef struct {
	fr *FeedRef
	mr *MessageRef
	br *BlobRef // payload/content ref
}

var _ Ref = (*StorageRef)(nil)

// currently all references are 32bytes long
// one additonal byte for tagging the type
const binrefSize = 33

func (ref StorageRef) valid() (StorageRefType, error) {
	i := 0
	var t StorageRefType = StorageRefUndefined
	if ref.fr != nil {
		i++
		switch ref.fr.Algo {
		case RefAlgoFeedSSB1:
			t = StorageRefFeedLegacy
		case RefAlgoFeedProto:
			t = StorageRefFeedProto
		case RefAlgoFeedGabby:
			t = StorageRefFeedGabby
		default:
			return StorageRefUndefined, ErrInvalidRef
		}
	}
	if ref.mr != nil {
		i++
		t = StorageRefMessage
	}
	if ref.br != nil {
		i++
		t = StorageRefBlob
	}
	if i > 1 {
		return StorageRefUndefined, errors.Errorf("more than one ref in binref")
	}
	return t, nil
}

func (ref StorageRef) Ref() string {
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

func (ref StorageRef) Marshal() ([]byte, error) {
	b := make([]byte, binrefSize)
	n, err := ref.MarshalTo(b)
	b = b[:n]
	return b, err
}

func (ref *StorageRef) MarshalTo(data []byte) (n int, err error) {
	t, err := ref.valid()
	if err != nil {
		return 0, err
	}
	switch t {
	case StorageRefFeedLegacy:
		copy(data, append([]byte{0x01}, ref.fr.ID...))
	case StorageRefMessage:
		copy(data, append([]byte{0x02}, ref.mr.Hash...))
	case StorageRefBlob:
		copy(data, append([]byte{0x03}, ref.br.Hash...))
	case StorageRefFeedProto:
		copy(data, append([]byte{0x04}, ref.fr.ID...))
	case StorageRefFeedGabby:
		copy(data, append([]byte{0x05}, ref.fr.ID...))
	default:
		return 0, errors.Wrapf(ErrInvalidRefType, "invalid binref type: %x", t)
	}
	return binrefSize, nil
}

func (ref *StorageRef) Unmarshal(data []byte) error {
	if n := len(data); n != binrefSize {
		return ErrRefLen{algo: "unknown", n: n}
	}
	switch data[0] {
	case 0x01:
		ref.fr = &FeedRef{
			ID:   data[1:],
			Algo: RefAlgoFeedSSB1,
		}
	case 0x02:
		ref.mr = &MessageRef{
			Hash: data[1:],
			Algo: RefAlgoMessageSSB1,
		}
	case 0x03:
		ref.br = &BlobRef{
			Hash: data[1:],
			Algo: RefAlgoBlobSSB1,
		}

	case 0x04:
		ref.fr = &FeedRef{
			ID:   data[1:],
			Algo: RefAlgoFeedProto,
		}

	case 0x05:
		ref.fr = &FeedRef{
			ID:   data[1:],
			Algo: RefAlgoFeedGabby,
		}
	default:
		return errors.Wrapf(ErrInvalidRefType, "invalid binref type: %x", data[0])
	}
	return nil
}

func (ref *StorageRef) Size() int {
	return binrefSize
}

func (ref StorageRef) MarshalJSON() ([]byte, error) {
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

func (ref *StorageRef) UnmarshalJSON(data []byte) error {
	// spew.Dump(ref)
	return errors.Errorf("TODO:json")
}

func (ref StorageRef) GetRef(t StorageRefType) (Ref, error) {
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
	case StorageRefFeedLegacy:
		ret = ref.fr
	case StorageRefMessage:
		ret = ref.mr
	case StorageRefBlob:
		ret = ref.br
	default:
		return nil, errors.Wrapf(ErrInvalidRefType, "invalid binref type: %x", t)
	}
	return ret, nil
}

func NewStorageRefFromString(s string) (*StorageRef, error) {
	r, err := ParseRef(s)
	if err != nil {
		return nil, errors.Wrap(err, "binref: not a ssb ref")
	}
	return NewStorageRef(r)
}

func NewStorageRef(r Ref) (*StorageRef, error) {
	var br StorageRef
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
