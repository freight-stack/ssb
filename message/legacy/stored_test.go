package legacy

import (
	"encoding/json"
	"testing"

	"go.cryptoscope.co/ssb"

	"go.cryptoscope.co/ssb/internal/stored"

	"github.com/stretchr/testify/require"
)

func TestAbstractStored(t *testing.T) {
	r := require.New(t)

	var m stored.Message
	m.Author = testMessages[1].Author
	m.Raw = testMessages[1].Input

	var s StoredMessage
	s.internal = m

	var a ssb.Message = s

	c := a.Content()
	r.NotNil(c)
	r.True(len(c) > 0)

	var contentMap map[string]interface{}
	err := json.Unmarshal(c, &contentMap)
	r.NoError(err)
	r.NotNil(contentMap["type"])

	author := a.Author()
	r.Equal(m.Author.ID, author.ID)
}
