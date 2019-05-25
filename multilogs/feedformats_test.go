package multilogs

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"go.cryptoscope.co/ssb/message/gabbygrove"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/multilog"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/protochain"
	"go.cryptoscope.co/ssb/repo"
)

func TestFormatsSimple(t *testing.T) {
	tctx := context.TODO()
	r := require.New(t)
	a := assert.New(t)

	rpath := filepath.Join("testrun", t.Name())
	os.RemoveAll(rpath)

	testRepo := repo.New(rpath)

	rl, err := repo.OpenLog(testRepo)

	r.NoError(err, "failed to open root log")
	seq, err := rl.Seq().Value()
	r.NoError(err, "failed to get log seq")
	r.Equal(margaret.BaseSeq(-1), seq, "not empty")

	userFeeds, _, userFeedsServe, err := OpenUserFeeds(testRepo)
	r.NoError(err, "failed to get user feeds multilog")

	killServe, cancel := context.WithCancel(tctx)
	defer cancel()
	errc := make(chan error)
	go func() {
		err := userFeedsServe(killServe, rl, true)
		errc <- errors.Wrap(err, "failed to pump log into userfeeds multilog")
	}()

	type testCase struct {
		ff    string
		pubfn func(margaret.Log, multilog.MultiLog, *ssb.KeyPair) (ssb.Publisher, error)
	}
	var testCases = []testCase{
		{ssb.RefAlgoProto, protochain.NewPublisher}, //
		{ssb.RefAlgoEd25519, OpenPublishLog},        // crappy
		{ssb.RefAlgoGabby, gabbygrove.NewPublisher}, //
	}

	staticRand := rand.New(rand.NewSource(42))
	for _, tc := range testCases {

		testAuthor, err := ssb.NewKeyPair(staticRand)
		r.NoError(err)
		testAuthor.Id.Algo = tc.ff

		authorLog, err := userFeeds.Get(testAuthor.Id.StoredAddr())
		r.NoError(err)

		w, err := tc.pubfn(rl, userFeeds, testAuthor)
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
			t.Logf("msg:%d\n%s", i, storedMsg.ContentBytes())
			a.NotNil(storedMsg.Key(), "msg:%d - key", i)

			if i != 0 {
				a.NotNil(storedMsg.Previous(), "msg:%d - previous", i)
			} else {
				a.Nil(storedMsg.Previous(), "msg:%d - previous", i)
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
	}
}
