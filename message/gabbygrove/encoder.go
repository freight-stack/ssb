package gabbygrove

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	"github.com/ugorji/go/codec"
	"go.cryptoscope.co/ssb"
	"golang.org/x/crypto/ed25519"
)

// CypherLinkCBORTag is the CBOR tag for a (ssb) cypherlink
// from https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml#tags
// 888 is WIP and currently unused
const CypherLinkCBORTag = 888

// GetCBORHandle returns a codec.CborHandle with an extension
// yet to be registerd for SSB References as CBOR tag XXX
func GetCBORHandle() (h *codec.CborHandle) {
	h = new(codec.CborHandle)
	h.IndefiniteLength = false // no streaming
	h.Canonical = true         // sort map keys
	h.SignedInteger = true

	var cExt BinRefExt
	h.SetInterfaceExt(reflect.TypeOf(&BinaryRef{}), CypherLinkCBORTag, cExt)
	return h
}

func NewEncoder(author *ssb.KeyPair) *cborEnc {
	pe := &cborEnc{}
	pe.kp = author
	return pe
}

type cborEnc struct {
	kp *ssb.KeyPair
}

func (e *cborEnc) Encode(sequence uint64, prev *BinaryRef, val interface{}) (*Transfer, *ssb.MessageRef, error) {
	contentHash := sha256.New()
	contentBuf := &bytes.Buffer{}
	w := io.MultiWriter(contentHash, contentBuf)

	switch tv := val.(type) {
	case []byte:
		io.Copy(w, bytes.NewReader(tv))
	case string:
		io.Copy(w, strings.NewReader(tv))
	default:
		err := json.NewEncoder(w).Encode(val)
		if err != nil {
			return nil, nil, errors.Wrap(err, "json content encoding failed")
		}
	}

	var evt Event
	if sequence > 1 {
		if prev == nil {
			return nil, nil, errors.Errorf("encode: previous can only be nil on the first message")
		}
		evt.Previous = prev
	}
	evt.Sequence = sequence

	var err error
	evt.Author, err = fromRef(e.kp.Id)
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid author ref")
	}

	evt.Content.Hash, err = fromRef(&ssb.BlobRef{
		Hash: contentHash.Sum(nil),
		Algo: ssb.RefAlgoGabby,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to construct content reference")
	}
	evt.Content.Type = ContentTypeJSON // only supported one right now, will switch to cbor ones cipherlinks specifics have been defined
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid content ref")
	}
	evt.Content.Size = uint64(contentBuf.Len())
	contentBytes := contentBuf.Bytes()

	evtBytes, err := evt.MarshalCBOR()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to encode event")
	}

	var tr Transfer
	tr.Event = evtBytes
	tr.Signature = ed25519.Sign(e.kp.Pair.Secret[:], evtBytes)
	tr.Content = contentBytes

	return &tr, tr.Key(), nil
}

func (tr Transfer) Key() *ssb.MessageRef {
	signedEvtHash := sha256.New()
	io.Copy(signedEvtHash, bytes.NewReader(tr.Event))
	io.Copy(signedEvtHash, bytes.NewReader(tr.Signature))

	return &ssb.MessageRef{
		Hash: signedEvtHash.Sum(nil),
		Algo: ssb.RefAlgoGabby,
	}
}
