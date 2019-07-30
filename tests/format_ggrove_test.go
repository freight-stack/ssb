package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/sbot"
)

func TestGabbyFeedFromGo(t *testing.T) {
	r := require.New(t)

	ts := newSession(t, nil, nil)
	// hmac not supported on the js side
	// ts := newRandomSession(t)

	kp, err := ssb.NewKeyPair(nil)
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoFeedGabby

	ts.startGoBot(sbot.WithKeyPair(kp))
	s := ts.gobot

	before := `fromKey = testBob
	sbot.on('rpc:connect', (rpc) => {
		pull(
			rpc.createHistoryStream({id: fromKey}),
			pull.collect((err, msgs) => {
				t.error(err)
				t.equal(msgs.length,3)
				console.warn('Messages: '+msgs.length)
				// console.warn(JSON.stringify(msgs))
				sbot.gabbygrove.verify(msgs[0], (err, evt) => {
					t.error(err, 'verified msg[0]')
					t.ok(evt)
					t.end()
				})
			})
		)
	})
	
	setTimeout(run, 3000) // give go bot a moment to publish
	// following is blocked on proper feed format support with new suffixes
`

	alice := ts.startJSBot(before, "")

	var tmsgs = []interface{}{
		map[string]interface{}{
			"type":  "ex-message",
			"hello": "world",
		},
		map[string]interface{}{
			"type":      "contact",
			"contact":   alice.Ref(),
			"following": true,
		},
		map[string]interface{}{
			"type":  "message",
			"text":  "whoops",
			"fault": true,
		},
	}
	for i, msg := range tmsgs {
		newSeq, err := s.PublishLog.Append(msg)
		r.NoError(err, "failed to publish test message %d", i)
		r.NotNil(newSeq)
	}

	// test is currently borked because we get fake messages back

	<-ts.doneJS

	// aliceLog, err := s.UserFeeds.Get(alice.StoredAddr())
	// r.NoError(err)

	// aliceSeq, err := aliceLog.Seq().Value()
	// r.NoError(err)
	// r.Equal(2, aliceSeq.(margaret.Seq).Seq())

	// seqMsg, err := aliceLog.Get(margaret.BaseSeq(2))
	// r.NoError(err)
	// msg, err := s.RootLog.Get(seqMsg.(margaret.BaseSeq))
	// r.NoError(err)
	// storedMsg, ok := msg.(ssb.Message)
	// r.True(ok, "wrong type of message: %T", msg)
	// r.Equal(storedMsg.Seq(), margaret.BaseSeq(3).Seq())
	time.Sleep(1 * time.Second)

	ts.wait()
}
