package message

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/margaret"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/legacy"
	"go.cryptoscope.co/ssb/message/multimsg"
	"go.cryptoscope.co/ssb/multilogs"
	"go.cryptoscope.co/ssb/repo"
)

func TestFormatsSimple(t *testing.T) {
	r := require.New(t)

	rpath := filepath.Join("testrun", t.Name())
	os.RemoveAll(rpath)

	testRepo := repo.New(rpath)

	rl, err := repo.OpenLog(testRepo)

	r.NoError(err, "failed to open root log")
	seq, err := rl.Seq().Value()
	r.NoError(err, "failed to get log seq")
	r.Equal(margaret.BaseSeq(-1), seq, "not empty")

	userFeeds, _, userFeedsServe, err := multilogs.OpenUserFeeds(testRepo)
	r.NoError(err, "failed to get user feeds multilog")

	type testCase struct {
		ff string
		// pubfn func(margaret.Log, multilog.MultiLog, *ssb.KeyPair) (ssb.Publisher, error)
	}
	var testCases = []testCase{
		{ssb.RefAlgoProto},   //
		{ssb.RefAlgoEd25519}, // crappy
		{ssb.RefAlgoGabby},   //
	}

	staticRand := rand.New(rand.NewSource(42))
	for _, tc := range testCases {

		t.Run(tc.ff, func(t *testing.T) {
			r := require.New(t)
			a := assert.New(t)

			testAuthor, err := ssb.NewKeyPair(staticRand)
			r.NoError(err)
			testAuthor.Id.Algo = tc.ff

			authorLog, err := userFeeds.Get(testAuthor.Id.StoredAddr())
			r.NoError(err)

			w, err := OpenPublishLog(rl, userFeeds, testAuthor)
			r.NoError(err)

			var tmsgs = []interface{}{
				map[string]interface{}{
					"type":  "about",
					"about": testAuthor.Id.Ref(),
					"name":  "test user",
				},
				map[string]interface{}{
					"type":      "contact",
					"contact":   "@p13zSAiOpguI9nsawkGijsnMfWmFd5rlUNpzekEE+vI=.ed25519",
					"following": true,
				},
				map[string]interface{}{
					"type": "text",
					"text": `# hello world!`,
				},
			}
			for i, msg := range tmsgs {
				mr, err := w.Publish(msg)
				r.NoError(err, "failed to pour test message %d", i)
				r.NotNil(mr)
				err = userFeedsServe(context.TODO(), rl, false)
				r.NoError(err)
				currSeq, err := authorLog.Seq().Value()
				r.NoError(err, "failed to get log seq")
				r.Equal(margaret.BaseSeq(i), currSeq, "failed to ")
			}

			latest, err := authorLog.Seq().Value()
			r.NoError(err, "failed to get log seq")
			r.Equal(margaret.BaseSeq(2), latest, "not empty %s", tc.ff)

			for i := 0; i < len(tmsgs); i++ {
				rootSeq, err := authorLog.Get(margaret.BaseSeq(i))
				r.NoError(err)
				storedV, err := rl.Get(rootSeq.(margaret.Seq))
				r.NoError(err)
				storedMsg, ok := storedV.(ssb.Message)
				r.True(ok)
				t.Logf("msg:%d\n%s", i, storedMsg.ValueContentJSON())
				a.NotNil(storedMsg.Key(), "msg:%d - key", i)

				// previous is correctly set
				if i != 0 {
					a.NotNil(storedMsg.Previous(), "msg:%d - previous", i)
					// get previous message
					prevV, err := authorLog.Get(margaret.BaseSeq(i - 1))
					r.NoError(err)
					prevSeq, ok := prevV.(margaret.Seq)
					r.True(ok, "got:%T", prevV)
					prevV, err = rl.Get(prevSeq)
					r.NoError(err)
					prevMsg, ok := prevV.(ssb.Message)
					r.True(ok, "got:%T", prevV)

					a.Equal(prevMsg.Key().Hash, storedMsg.Previous().Hash, "msg:%d - wrong previous", i)
				} else {
					a.Nil(storedMsg.Previous(), "msg:%d - previous", i)
				}

				a.Equal(int64(i+1), storedMsg.Seq(), "msg:%d - has incorrect sequence")

				// verifies
				mm, ok := storedV.(multimsg.MultiMessage)
				r.True(ok)
				switch tc.ff {
				case ssb.RefAlgoEd25519:
					msg, ok := mm.AsLegacy()
					r.True(ok)

					_, _, err = legacy.Verify(msg.Raw_, nil)
					r.NoError(err)

				case ssb.RefAlgoProto:
					msg, ok := mm.AsProto()
					r.True(ok)
					a.True(msg.Verify(), "proto failed to validate msg:%d", i)

				case ssb.RefAlgoGabby:
					g, ok := mm.AsGabby()
					r.True(ok)
					a.True(g.Verify(), "gabby failed to validate msg:%d", i)

				default:
					r.FailNow("unhandled feed format", "format:%s", tc.ff)
				}

				// a.NotNil(storedMsg.ContentBytes(), "msg:%d - raw", i)
				// a.Contains(string(storedMsg.Raw), `"signature": "`)
				// a.Contains(string(storedMsg.Raw), fmt.Sprintf(`"sequence": %d`, i+1))
				// a.True(len(storedMsg.Offchain) > 0, "no content in offchain")

				// var checKmsg struct {
				// 	Content *ssb.OffchainMessageRef `json:"content"`
				// }
				// err = json.Unmarshal(storedMsg.Raw, &checKmsg)
				// a.NoError(err)
			}
		})
	}
}
