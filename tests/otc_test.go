package tests

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/legacy"
	"go.cryptoscope.co/ssb/sbot"
)

func XTestContentFeedFromJS(t *testing.T) {
	a := assert.New(t)
	r := require.New(t)
	const n = 23

	ts := newRandomSession(t)

	kp, err := ssb.NewKeyPair(nil)
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoProto

	ts.startGoBot(sbot.WithKeyPair(kp))
	bob := ts.gobot

	r.True(strings.HasSuffix(bob.KeyPair.Id.Ref(), ".proto-v1"))

	alice := ts.startJSBot(`
	function mkMsg(msg) {
		return function(cb) {
			sbot.contentStream.publish(msg, cb)
		}
	}
	n = 23
	let msgs = []
	for (var i = n; i>0; i--) {
		msgs.push(mkMsg({type:"offchain", text:"foo", test:i}))
	}

	// be done when the other party is done
	sbot.on('rpc:connect', rpc => rpc.on('closed', exit))

	parallel(msgs, function(err, results) {
		t.error(err, "parallel of publish")
		t.equal(n, results.length, "message count")
		run() // triggers connect and after block
	})
`, ``)

	newSeq, err := bob.PublishLog.Append(map[string]interface{}{
		"type":      "contact",
		"contact":   alice.Ref(),
		"following": true,
	})
	r.NoError(err, "failed to publish contact message")
	r.NotNil(newSeq)

	<-ts.doneJS

	aliceLog, err := bob.UserFeeds.Get(alice.StoredAddr())
	r.NoError(err)
	seq, err := aliceLog.Seq().Value()
	r.NoError(err)
	r.Equal(margaret.BaseSeq(n-1), seq)

	for i := 0; i < n; i++ {
		// only one feed in log - directly the rootlog sequences
		seqMsg, err := aliceLog.Get(margaret.BaseSeq(i))
		r.NoError(err)
		r.Equal(seqMsg, margaret.BaseSeq(i+1))

		msg, err := bob.RootLog.Get(seqMsg.(margaret.BaseSeq))
		r.NoError(err)
		storedMsg, ok := msg.(legacy.StoredMessage)
		r.True(ok, "wrong type of message: %T", msg)
		r.Equal(storedMsg.Sequence_, margaret.BaseSeq(i+1))

		type testWrap struct {
			Author  ssb.FeedRef
			Content struct {
				Type, Text string
				Test       int
			}
		}
		var m testWrap
		err = json.Unmarshal(storedMsg.Raw_, &m)
		r.NoError(err)
		r.True(alice.Equal(&m.Author), "wrong author")
		a.Equal(m.Content.Type, "offchain")
		a.Equal(m.Content.Text, "foo")
		a.Equal(m.Content.Test, n-i, "wrong I on msg: %d", i)
		t.Log(string(storedMsg.Raw_))
	}
}

func TestContentFeedFromGo(t *testing.T) {
	r := require.New(t)

	ts := newRandomSession(t)
	// ts := newSession(t, nil, nil)

	// make offchain ID
	kp, err := ssb.NewKeyPair(nil)
	r.NoError(err)
	kp.Id.Algo = ssb.RefAlgoProto

	ts.startGoBot(sbot.WithKeyPair(kp))
	s := ts.gobot

	r.Contains(s.KeyPair.Id.Ref(), ".proto")

	before := `fromKey = testBob
	sbot.on('rpc:connect', (rpc) => {
		pull(
			rpc.protochain.binaryStream({id: fromKey}),
			pull.collect((err, msgs) => {
				t.error(err)
				t.equal(msgs.length,3)
				console.warn('Messages: '+msgs.length)
				console.warn(JSON.stringify(msgs))
				sbot.protochain.verify(msgs[0], (err, evt) => {
					t.error(err, 'verified msg[0]')
					t.ok(evt)
					t.end()
				})
			})
		)
			
		// rpc.on('closed', () => {
		// 	t.comment('now should have feed:' + fromKey)
		// 	pull(
		// 		sbot.contentStream.getContentStream({id: fromKey}),
		// 		pull.collect((err, msgs) => {
		// 			t.error(err)
		// 			console.warn('BHC: '+msgs.length)
		// 			console.warn(JSON.stringify(msgs))
		// 			t.end()
		// 		})
		// 	)
		// })
		// setTimeout(() => {
		// 	t.comment('now should have feed:' + fromKey)
		// 	pull(
		// 		sbot.contentStream.getContentStream({id: fromKey}),
		// 		pull.collect((err, msgs) => {
		// 			t.error(err)
		// 			console.warn('Messages: '+msgs.length)
		// 			console.warn(JSON.stringify(msgs))
		// 			// t.end()
		// 		})
		// 	)
		// },1000)
	})
	
	setTimeout(run, 3000) // give go bot a moment to publish
	// sbot.publish({type: 'contact', contact: fromKey, following: true}, function(err, msg) {
	// 	t.error(err, 'follow:' + fromKey)

	// 	sbot.friends.get({src: alice.id, dest: fromKey}, function(err, val) {
	// 		t.error(err, 'friends.get of new contact')
	// 		t.equals(val[alice.id], true, 'is following')

	// 		t.comment('shouldnt have bobs feed:' + fromKey)
	// 		pull(
	// 			sbot.createUserStream({id:fromKey}),
	// 			pull.collect(function(err, vals){
	// 				t.error(err)
	// 				t.equal(0, vals.length)
	// 				sbot.publish({type: 'about', about: fromKey, name: 'test bob'}, function(err, msg) {
	// 					t.error(err, 'about:' + msg.key)
	// 					setTimeout(run, 3000) // give go bot a moment to publish
	// 				})
	// 			})
	// 		)
	// 	}) // friends.get
	// }) // publish
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
