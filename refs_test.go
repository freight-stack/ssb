package ssb

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/shurcooL/go-goon"
	"github.com/stretchr/testify/assert"
)

func TestParseRef(t *testing.T) {
	a := assert.New(t)
	var tcases = []struct {
		ref  string
		err  error
		want Ref
	}{
		{"xxxx", ErrInvalidRef, nil},
		{"+xxx.foo", ErrInvalidHash, nil},
		{"@xxx.foo", ErrInvalidHash, nil},

		{"%wayTooShort.sha256", ErrInvalidHash, nil},
		{"&tooShort.sha256", NewHashLenError(6), nil},
		{"@tooShort.ed25519", NewFeedRefLenError(6), nil},
		{"&c29tZU5vbmVTZW5zZQo=.sha256", NewHashLenError(14), nil},

		{"@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519", nil, &FeedRef{
			ID:   []byte{201, 239, 144, 51, 79, 98, 61, 192, 201, 15, 166, 47, 65, 136, 232, 65, 206, 236, 44, 95, 200, 22, 25, 141, 108, 74, 160, 119, 52, 40, 222, 84},
			Algo: RefAlgoEd25519,
		}},

		{"@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.proto", nil, &FeedRef{
			ID:   []byte{201, 239, 144, 51, 79, 98, 61, 192, 201, 15, 166, 47, 65, 136, 232, 65, 206, 236, 44, 95, 200, 22, 25, 141, 108, 74, 160, 119, 52, 40, 222, 84},
			Algo: RefAlgoProto,
		}},

		{"&84SSLNv5YdDVTdSzN2V1gzY5ze4lj6tYFkNyT+P28Qs=.sha256", nil, &BlobRef{
			Hash: []byte{243, 132, 146, 44, 219, 249, 97, 208, 213, 77, 212, 179, 55, 101, 117, 131, 54, 57, 205, 238, 37, 143, 171, 88, 22, 67, 114, 79, 227, 246, 241, 11},
			Algo: RefAlgoSHA256,
		}},

		{"%2jDrrJEeG7PQcCLcisISqarMboNpnwyfxLnwU1ijOjc=.sha256", nil, &MessageRef{
			Hash: []byte{218, 48, 235, 172, 145, 30, 27, 179, 208, 112, 34, 220, 138, 194, 18, 169, 170, 204, 110, 131, 105, 159, 12, 159, 196, 185, 240, 83, 88, 163, 58, 55},
			Algo: RefAlgoSHA256,
		}},

		{"2jDrrJEeG7PQcCLcisISqarMboNpnwyfxLnwU1ijOjc=.sha256.offchain", nil, &OffchainMessageRef{
			Hash: []byte{218, 48, 235, 172, 145, 30, 27, 179, 208, 112, 34, 220, 138, 194, 18, 169, 170, 204, 110, 131, 105, 159, 12, 159, 196, 185, 240, 83, 88, 163, 58, 55},
			Algo: RefAlgoSHA256,
		}},
	}
	for i, tc := range tcases {
		r, err := ParseRef(tc.ref)
		if tc.err == nil {
			if !a.NoError(err, "got error on test %d", i) {
				continue
			}
			input := a.Equal(tc.ref, tc.want.Ref(), "test %d input<>output failed", i)
			want := a.Equal(tc.want.Ref(), r.Ref(), "test %d re-encode failed", i)
			if !input || !want {
				goon.Dump(r)
			}
		} else {
			a.EqualError(errors.Cause(err), tc.err.Error(), "%d wrong error", i)
		}
	}
}
