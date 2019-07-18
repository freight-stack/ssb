package gabbygrove

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"strings"

	proto "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"go.cryptoscope.co/ssb"
	"golang.org/x/crypto/ed25519"
)

func NewEncoder(author *ssb.KeyPair) *protoEnc {
	pe := &protoEnc{}
	pe.kp = author
	return pe
}

type protoEnc struct {
	kp *ssb.KeyPair
}

func (e *protoEnc) Encode(sequence uint64, prev *BinaryRef, val interface{}) (*Transfer, *ssb.MessageRef, error) {
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
	evt.Author, err = FromRef(e.kp.Id)
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid author ref")
	}
	evt.Content = &Event_Content{}
	evt.Content.Hash, err = FromRef(&ssb.BlobRef{
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

	evtBytes, err := proto.Marshal(&evt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to encode metadata")
	}

	var tr Transfer
	tr.Event = evtBytes
	tr.Signature = ed25519.Sign(e.kp.Pair.Secret[:], evtBytes)
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
