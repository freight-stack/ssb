package gabbygrove_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/codec/msgpack"
	"go.cryptoscope.co/margaret/offset2"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message"
	"go.cryptoscope.co/ssb/message/gabbygrove"
	"go.cryptoscope.co/ssb/multilogs"
	"go.cryptoscope.co/ssb/repo"
)

func TestPublish(t *testing.T) {
	r := require.New(t)

	// testStore := mem.New()
	// might be nice to have a mem-based multilog?

	os.RemoveAll("testrun")
	testRepoFolder := filepath.Join("testrun", t.Name())
	tesRepo := repo.New(testRepoFolder)
	testStore, err := offset2.Open(filepath.Join(testRepoFolder, "log"), msgpack.New(&message.MultiMessage{}))
	r.NoError(err)
	testStore = message.NewWrappedLog(testStore)

	userFeeds, _, updateUserFeeds, err := multilogs.OpenUserFeeds(tesRepo)
	r.NoError(err)

	beef := bytes.Repeat([]byte("beef"), 8)
	testKP, err := ssb.NewKeyPair(bytes.NewReader(beef))
	r.NoError(err)
	testKP.Id.Algo = ssb.RefAlgoProto

	p, err := gabbygrove.NewPublisher(testStore, userFeeds, testKP)
	r.NoError(err)

	testContent := []interface{}{
		map[string]interface{}{
			"type": "test",
			"seq":  0,
		},

		map[string]interface{}{
			"type": "test",
			"seq":  1,
		},

		"just A string.noBox", // should be box

		map[string]interface{}{
			"type":       "test",
			"seq":        2,
			"spectating": true,
		},
	}

	for i, tc := range testContent {
		ref, err := p.Publish(tc)
		r.NoError(err, "failed to publish msg %d", i)
		r.NotNil(ref)

		err = updateUserFeeds(context.TODO(), testStore, false)
		r.NoError(err, "failed to update sublogs on msg %d", i)

		currSeq, err := testStore.Seq().Value()
		r.NoError(err)
		r.NotEqual(currSeq, margaret.SeqEmpty)
		r.Equal(currSeq, margaret.BaseSeq(i))

		storedV, err := testStore.Get(currSeq.(margaret.BaseSeq))
		r.NoError(err)

		multiMsg, ok := storedV.(message.MultiMessage)
		r.True(ok)

		r.NotNil(multiMsg.Key())

		// raw stores the transfer encoding
		msgv, err := multiMsg.ByType(message.Proto)
		r.NoError(err)
		tr := msgv.(*gabbygrove.Transfer)

		evt, err := tr.UnmarshaledEvent()
		r.NoError(err)

		r.Equal(uint64(i)+1, evt.Sequence)

		r.True(tr.Verify(), "unable to verify")

		if i == 0 {
			r.Nil(evt.Previous, "previous nil on first message")
		} else { // check previous
			r.NotNil(evt.Previous, "previous should be not nil on later msgs")

			// get previous message
			prevV, err := testStore.Get(margaret.BaseSeq(i - 1))
			r.NoError(err)
			prevMsg, ok := prevV.(message.MultiMessage)
			r.True(ok)

			// compare reference
			prevRef, err := evt.Previous.GetRef(gabbygrove.RefType_MessageRef)
			r.NoError(err)
			mr := prevRef.(*ssb.MessageRef)
			r.Equal(prevMsg.Key().Hash, mr.Hash)
		}
	}

}

func TestMultipleFeeds(t *testing.T) {
	r := require.New(t)

	os.RemoveAll("testrun")
	testRepoFolder := filepath.Join("testrun", t.Name())
	tesRepo := repo.New(testRepoFolder)
	testStore, err := offset2.Open(filepath.Join(testRepoFolder, "log"), msgpack.New(&message.MultiMessage{}))
	r.NoError(err)
	testStore = message.NewWrappedLog(testStore)

	userFeeds, _, updateUserFeeds, err := multilogs.OpenUserFeeds(tesRepo)
	r.NoError(err)

	keypairAlice, err := ssb.NewKeyPair(bytes.NewReader(bytes.Repeat([]byte("acab"), 8)))
	r.NoError(err)
	keypairAlice.Id.Algo = ssb.RefAlgoProto

	keypairBob, err := ssb.NewKeyPair(bytes.NewReader(bytes.Repeat([]byte("beef"), 8)))
	r.NoError(err)
	keypairBob.Id.Algo = ssb.RefAlgoProto

	alice, err := gabbygrove.NewPublisher(testStore, userFeeds, keypairAlice)
	r.NoError(err)
	bob, err := gabbygrove.NewPublisher(testStore, userFeeds, keypairBob)
	r.NoError(err)

	testContent := []interface{}{
		map[string]interface{}{
			"type": "test",
			"from": "alice",
			"seq":  0,
		},

		map[string]interface{}{
			"type": "test",
			"from": "bob",
			"seq":  0,
		},

		map[string]interface{}{
			"type": "test",
			"from": "alice",
			"seq":  1,
		},

		map[string]interface{}{
			"type": "test",
			"from": "bob",
			"seq":  1,
		},

		map[string]interface{}{
			"type": "test",
			"from": "alice",
			"seq":  2,
		},

		map[string]interface{}{
			"type": "test",
			"from": "bob",
			"seq":  2,
		},
	}

	for i, tc := range testContent {
		err = updateUserFeeds(context.TODO(), testStore, false)
		r.NoError(err, "failed to update sublogs on msg %d", i)

		if i%2 == 0 { // even is alice
			ref, err := alice.Publish(tc)
			r.NoError(err, "failed to publish msg %d", i)
			r.NotNil(ref)

		} else { // odd is from bob
			ref, err := bob.Publish(tc)
			r.NoError(err, "failed to publish msg %d", i)
			r.NotNil(ref)
		}
	}

	currSeq, err := testStore.Seq().Value()
	r.NoError(err)
	r.NotEqual(currSeq, margaret.SeqEmpty)
	r.Equal(currSeq, margaret.BaseSeq(5)) // 0 indexed

	a := assert.New(t)

	// check all the sequences for alice
	for i, seq := range []margaret.BaseSeq{0, 2, 4} {
		msgV, err := testStore.Get(seq)
		r.NoError(err)

		multiMsg, ok := msgV.(message.MultiMessage)
		r.True(ok)
		// raw stores the transfer encoding
		msgv, err := multiMsg.ByType(message.Proto)
		r.NoError(err)
		tr := msgv.(*gabbygrove.Transfer)

		evt, err := tr.UnmarshaledEvent()
		r.NoError(err)
		a.Equal(uint64(i)+1, evt.Sequence)
	}

	// check all the sequences for bob
	for i, seq := range []margaret.BaseSeq{1, 3, 5} {
		msgV, err := testStore.Get(seq)
		r.NoError(err)

		multiMsg, ok := msgV.(message.MultiMessage)
		r.True(ok)
		// raw stores the transfer encoding
		msgv, err := multiMsg.ByType(message.Proto)
		r.NoError(err)
		tr := msgv.(*gabbygrove.Transfer)

		evt, err := tr.UnmarshaledEvent()
		r.NoError(err)
		a.Equal(uint64(i)+1, evt.Sequence)
	}
}
