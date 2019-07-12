package ssb

import (
	"bytes"
	"encoding"
	"encoding/base64"
	stderr "errors"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"

	"go.cryptoscope.co/librarian"
	"go.cryptoscope.co/netwrap"
	"go.cryptoscope.co/secretstream"
)

const (
	RefAlgoSHA256  = "sha256"
	RefAlgoEd25519 = "ed25519"
)

// Common errors for invalid references
var (
	ErrInvalidRef     = stderr.New("ssb: Invalid Ref")
	ErrInvalidRefType = stderr.New("ssb: Invalid Ref Type")
	ErrInvalidRefAlgo = stderr.New("ssb: Invalid Ref Algo")
	ErrInvalidSig     = stderr.New("ssb: Invalid Signature")
	ErrInvalidHash    = stderr.New("ssb: Invalid Hash")
)

type ErrRefLen struct {
	algo string
	n    int
}

func (e ErrRefLen) Error() string {
	return fmt.Sprintf("ssb: Invalid reference len for %s: %d", e.algo, e.n)
}

func NewFeedRefLenError(n int) error {
	return ErrRefLen{algo: RefAlgoEd25519, n: n}
}

func NewHashLenError(n int) error {
	return ErrRefLen{algo: RefAlgoSHA256, n: n}
}

func ParseRef(str string) (Ref, error) {
	if len(str) == 0 {
		return nil, ErrInvalidRef
	}

	if strings.HasSuffix(str, offchainMsgRefSuffix) {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(str, offchainMsgRefSuffix))
		if err != nil {
			return nil, errors.Wrapf(ErrInvalidHash, "ocm b64 decode failed (%s)", err)
		}
		if n := len(raw); n != 32 {
			return nil, NewHashLenError(n)
		}
		return &OffchainMessageRef{
			Hash: raw,
			Algo: RefAlgoSHA256,
		}, nil
	}

	split := strings.Split(str[1:], ".")
	if len(split) < 2 {
		return nil, ErrInvalidRef
	}

	raw, err := base64.StdEncoding.DecodeString(split[0])
	if err != nil { // ???
		raw, err = base64.URLEncoding.DecodeString(split[1])
		if err != nil {
			return nil, errors.Wrapf(ErrInvalidHash, "b64 decode failed (%s)", err)
		}
	}

	switch str[0:1] {
	case "@":
		if split[1] != RefAlgoEd25519 {
			return nil, ErrInvalidRefAlgo
		}
		if n := len(raw); n != 32 {
			return nil, NewFeedRefLenError(n)
		}
		return &FeedRef{
			ID:       raw,
			Algo:     RefAlgoEd25519,
			Offchain: strings.HasSuffix(str, ".offchain"),
		}, nil
	case "%":
		if split[1] != RefAlgoSHA256 {
			return nil, ErrInvalidRefAlgo
		}
		if n := len(raw); n != 32 {
			return nil, NewHashLenError(n)
		}
		return &MessageRef{
			Hash: raw,
			Algo: RefAlgoSHA256,
		}, nil
	case "&":
		if split[1] != RefAlgoSHA256 {
			return nil, ErrInvalidRefAlgo
		}
		if n := len(raw); n != 32 {
			return nil, NewHashLenError(n)
		}
		return &BlobRef{
			Hash: raw,
			Algo: RefAlgoSHA256,
		}, nil
	}

	return nil, ErrInvalidRefType
}

type Ref interface {
	Ref() string
}

// MessageRef defines the content addressed version of a ssb message, identified it's hash.
type MessageRef struct {
	Hash []byte
	Algo string
}

func (ref MessageRef) Ref() string {
	return fmt.Sprintf("%%%s.%s", base64.StdEncoding.EncodeToString(ref.Hash), ref.Algo)
}

var (
	_ encoding.TextMarshaler   = (*MessageRef)(nil)
	_ encoding.TextUnmarshaler = (*MessageRef)(nil)
)

func (mr *MessageRef) MarshalText() ([]byte, error) {
	if len(mr.Hash) == 0 {
		return []byte{}, nil
	}
	return []byte(mr.Ref()), nil
}

func (mr *MessageRef) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*mr = MessageRef{}
		return nil
	}
	newRef, err := ParseMessageRef(string(text))
	if err != nil {
		return errors.Wrap(err, "message: unmarshal failed")
	}
	*mr = *newRef
	return nil
}

func (r *MessageRef) Scan(raw interface{}) error {
	switch v := raw.(type) {
	case []byte:
		if len(v) != 32 {
			return errors.Errorf("msgRef/Scan: wrong length: %d", len(v))
		}
		r.Hash = v
		r.Algo = RefAlgoSHA256
	case string:
		mr, err := ParseMessageRef(v)
		if err != nil {
			return errors.Wrap(err, "msgRef/Scan: failed to serialze from string")
		}
		*r = *mr
	default:
		return errors.Errorf("msgRef/Scan: unhandled type %T", raw)
	}
	return nil
}

func ParseMessageRef(s string) (*MessageRef, error) {
	ref, err := ParseRef(s)
	if err != nil {
		return nil, errors.Wrap(err, "messageRef: failed to parse ref")
	}
	newRef, ok := ref.(*MessageRef)
	if !ok {
		return nil, errors.Errorf("messageRef: not a message! %T", ref)
	}
	return newRef, nil
}

const offchainMsgRefSuffix = ".sha256.offchain"

type OffchainMessageRef struct {
	Hash []byte
	Algo string
}

func (ref OffchainMessageRef) Ref() string {
	return fmt.Sprintf("%s.%s.offchain", base64.StdEncoding.EncodeToString(ref.Hash), ref.Algo)
}

var (
	_ encoding.TextMarshaler   = (*OffchainMessageRef)(nil)
	_ encoding.TextUnmarshaler = (*OffchainMessageRef)(nil)
)

func (ocm *OffchainMessageRef) MarshalText() ([]byte, error) {
	return []byte(ocm.Ref()), nil
}

func (ocm *OffchainMessageRef) UnmarshalText(text []byte) error {
	newRef, err := ParseOffchainMessageRef(string(text))
	if err != nil {
		return err
	}
	*ocm = *newRef
	return nil
}

func ParseOffchainMessageRef(s string) (*OffchainMessageRef, error) {
	ref, err := ParseRef(s)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse OCM ref")
	}
	newRef, ok := ref.(*OffchainMessageRef)
	if !ok {
		return nil, errors.Errorf("parse OffchainMessageRef: not an OCM! %T", ref)
	}
	return newRef, nil
}

// FeedRef defines a publickey as ID with a specific algorithm (currently only ed25519)
type FeedRef struct {
	ID   []byte
	Algo string

	Offchain bool // denoets an feed with offchain encoded messages
}

func NewFeedRefEd25519(b []byte) (*FeedRef, error) {
	var r FeedRef
	r.Algo = RefAlgoEd25519
	if len(b) != 32 {
		return nil, ErrInvalidRef
	}
	r.ID = make([]byte, 32)
	copy(r.ID, b[:])
	return &r, nil
}

func (ref FeedRef) PubKey() ed25519.PublicKey {
	return ref.ID
}

// StoredAddr returns the key under which this ref is stored in the multilog system
// librarian uses a string but we used the bytes of the public key until now (32 vs 53 bytes per feed)
// but this looses different types of keys at that layer.
// TODO: could actually be a compact representation of the pubkey bytes
// with an additonal type byte but this _should_ make it work for now
func (ref FeedRef) StoredAddr() librarian.Addr {
	return librarian.Addr(ref.Ref())
}

func (ref FeedRef) Ref() string {
	s := fmt.Sprintf("@%s.%s", base64.StdEncoding.EncodeToString(ref.ID), ref.Algo)
	if ref.Offchain {
		s += ".offchain"
	}
	return s
}

func (ref FeedRef) Equal(b *FeedRef) bool {
	return bytes.Equal(ref.ID, b.ID)
}

var (
	_ encoding.TextMarshaler   = (*FeedRef)(nil)
	_ encoding.TextUnmarshaler = (*FeedRef)(nil)
)

func (fr *FeedRef) MarshalText() ([]byte, error) {
	return []byte(fr.Ref()), nil
}

func (fr *FeedRef) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*fr = FeedRef{}
		return nil
	}
	newRef, err := ParseFeedRef(string(text))
	if err != nil {
		return err
	}
	*fr = *newRef
	return nil
}

func (r *FeedRef) Scan(raw interface{}) error {
	switch v := raw.(type) {
	// TODO: add an extra byte/flag bits to denote algo and types
	// case []byte:
	// 	if len(v) != 32 {
	// 		return errors.Errorf("feedRef/Scan: wrong length: %d", len(v))
	// 	}
	// 	(*r).ID = v
	// 	(*r).Algo = "ed25519"

	case string:
		fr, err := ParseFeedRef(v)
		if err != nil {
			return errors.Wrap(err, "feedRef/Scan: failed to serialze from string")
		}
		*r = *fr
	default:
		return errors.Errorf("feedRef/Scan: unhandled type %T (see TODO)", raw)
	}
	return nil
}

// ParseFeedRef uses ParseRef and checks that it returns a *FeedRef
func ParseFeedRef(s string) (*FeedRef, error) {
	ref, err := ParseRef(s)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse ref")
	}
	newRef, ok := ref.(*FeedRef)
	if !ok {
		return nil, errors.Errorf("feedRef: not a feed! %T", ref)
	}
	return newRef, nil
}

// GetFeedRefFromAddr uses netwrap to get the secretstream address and then uses ParseFeedRef
func GetFeedRefFromAddr(addr net.Addr) (*FeedRef, error) {
	addr = netwrap.GetAddr(addr, secretstream.NetworkString)
	if addr == nil {
		return nil, errors.New("no shs-bs address found")
	}
	ssAddr := addr.(secretstream.Addr)
	return ParseFeedRef(ssAddr.String())
}

// BlobRef defines a static binary attachment reference, identified it's hash.
type BlobRef struct {
	Hash []byte
	Algo string
}

// Ref returns the BlobRef with the sigil &, it's base64 encoded hash and the used algo (currently only sha256)
func (ref BlobRef) Ref() string {
	return fmt.Sprintf("&%s.%s", base64.StdEncoding.EncodeToString(ref.Hash), ref.Algo)
}

// ParseBlobRef uses ParseRef and checks that it returns a *BlobRef
func ParseBlobRef(s string) (*BlobRef, error) {
	ref, err := ParseRef(s)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse ref")
	}
	newRef, ok := ref.(*BlobRef)
	if !ok {
		return nil, errors.Errorf("blobRef: not a blob! %T", ref)
	}
	return newRef, nil
}

// MarshalText encodes the BlobRef using Ref()
func (br *BlobRef) MarshalText() ([]byte, error) {
	return []byte(br.Ref()), nil
}

// UnmarshalText uses ParseBlobRef
func (br *BlobRef) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*br = BlobRef{}
		return nil
	}
	newBR, err := ParseBlobRef(string(text))
	if err != nil {
		return errors.Wrap(err, " BlobRef/UnmarshalText failed")
	}
	*br = *newBR
	return nil
}
