package ssb

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

func TestParseRef(t *testing.T) {
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
	}
	for i, tc := range tcases {
		r, err := ParseRef(tc.ref)
		if err != tc.err {
			assert.EqualError(t, err, tc.err.Error(), "%d wrong error", i)
		} else if tc.err == nil {
			assert.Equal(t, tc.want.Ref(), r.Ref(), "test %d failed", i)
		}
	}
}

func TestParseBranches(t *testing.T) {
	r := require.New(t)

	var got struct {
		Refs MessageRefs `json:"refs"`
	}
	var input = []byte(`{
		"refs": "%HG1p299uO2nCenG6YwR3DG33lLpcALAS/PI6/BP5dB0=.sha256"
	}`)

	err := json.Unmarshal(input, &got)
	r.NoError(err)
	r.Equal(1, len(got.Refs))
	r.Equal(got.Refs[0].Ref(), "%HG1p299uO2nCenG6YwR3DG33lLpcALAS/PI6/BP5dB0=.sha256")

	var asArray = []byte(`{
		"refs": [
			"%hCM+q/zsq8vseJKwIAAJMMdsAmWeSfG9cs8ed3uOXCc=.sha256",
			"%yJAzwPO7HSjvHRp7wrVGO4sbo9GHSwKk0BXOSiUr+bo=.sha256"
		]
	}`)

	err = json.Unmarshal(asArray, &got)
	require.NoError(t, err)
	r.Equal(2, len(got.Refs))
	r.Equal(got.Refs[0].Ref(), `%hCM+q/zsq8vseJKwIAAJMMdsAmWeSfG9cs8ed3uOXCc=.sha256`)
	r.Equal(got.Refs[1].Ref(), `%yJAzwPO7HSjvHRp7wrVGO4sbo9GHSwKk0BXOSiUr+bo=.sha256`)

	var empty = []byte(`{
		"refs": []
	}`)

	err = json.Unmarshal(empty, &got)
	require.NoError(t, err)
	r.Equal(0, len(got.Refs))
}
