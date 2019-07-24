/* Package protochain implements an alternative feed format for ssb.

This is highly experimental. See the README.md for more.

*/
package protochain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strings"

	"github.com/pkg/errors"
	"go.cryptoscope.co/ssb"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/auth"
)

func NewEncoder(author *ssb.KeyPair) *Encoder {
	pe := &Encoder{}
	pe.kp = author
	return pe
}

type Encoder struct {
	kp *ssb.KeyPair

	hmacSecret *[32]byte
}

func (e *Encoder) WithHMAC(in []byte) error {
	var k [32]byte
	n := copy(k[:], in)
	if n != 32 {
		return errors.Errorf("hmac key to short: %d", n)
	}
	e.hmacSecret = &k
	return nil
}

func (e *Encoder) Encode(sequence uint64, prev *BinaryRef, val interface{}) (*Transfer, *ssb.MessageRef, error) {
	contentHash := sha256.New()
	buf := &bytes.Buffer{}
	w := io.MultiWriter(contentHash, buf)

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
	evt.Content = &Event_Content{}
	evt.Content.Hash, err = fromRef(&ssb.BlobRef{
		Hash: contentHash.Sum(nil),
		Algo: ssb.RefAlgoSHA256,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to construct content reference")
	}
	evt.Content.Type = ContentType_JSON // only supported one right now
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid content ref")
	}
	evt.Content.Size_ = uint64(buf.Len())

	evt.Timestamp = 0

	evtBytes, err := evt.Marshal()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to encode metadata")
	}

	toSign := evtBytes
	if e.hmacSecret != nil {
		mac := auth.Sum(evtBytes, e.hmacSecret)
		toSign = mac[:]
	}

	var tr Transfer
	tr.Event = evtBytes
	tr.Signature = ed25519.Sign(e.kp.Pair.Secret[:], toSign)
	tr.Content = buf.Bytes()

	return &tr, tr.Key(), nil
}

func (tr Transfer) Key() *ssb.MessageRef {
	signedEvtHash := sha256.New()
	io.Copy(signedEvtHash, bytes.NewReader(tr.Event))
	io.Copy(signedEvtHash, bytes.NewReader(tr.Signature))

	return &ssb.MessageRef{
		Hash: signedEvtHash.Sum(nil),
		Algo: ssb.RefAlgoSHA256,
	}
}
