package tests

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/netwrap"
	"golang.org/x/crypto/nacl/auth"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message"
)

// first js creates an invite
// go will play introducer node
// second js peer will try to use/redeem the invite
func TestInviteJSCreate(t *testing.T) {

	r := require.New(t)

	os.Remove("invite.json")

	ts := newRandomSession(t)
	// ts := newSession(t, nil, nil)

	ts.startGoBot()
	bob := ts.gobot

	wrappedAddr := bob.Network.GetListenAddr()
	addr := fmt.Sprintf("net:%s", netwrap.GetAddr(wrappedAddr, "tcp").String())
	addr += "~shs:"
	addr += base64.StdEncoding.EncodeToString(bob.KeyPair.Id.ID)
	t.Log("addr:", addr)

	bob.PublishLog.Append(map[string]interface{}{
		"type":         "address",
		"availability": 1,
		"address":      addr,
	})

	// manual invite creation
	_ = `var fs = require('fs')
	var seed = require('crypto').randomBytes(32) //32 bytes of randomness
	var ssbKeys = require('ssb-keys')
	var invite_key = ssbKeys.generate('ed25519', seed)
	var invite_cap = require('ssb-config').caps.peerInvite
	
	sbot.on('rpc:connect', rpc => rpc.on('closed', exit))
	
	// TODO: follow bob
	
	sbot.publish(ssbKeys.signObj(invite_key, invite_cap,
		{
			type: 'peer-invite',
			invite: invite_key.id,
			host: alice.id,
		}),
		function (err, invite_msg) {
			t.error(err, "invite publish")
			var inv = JSON.stringify({
				seed: seed.toString('base64'),
				invite_msg:  invite_msg.key,
			})
			
			fs.writeFile('invite.json', inv, (err) => {  
				// throws an error, you could also catch it here
				if (err) throw err;
				
				// success case, the file was saved
				console.warn('invite saved!');
				run()
			});
		})`

	createInvite := fmt.Sprintf(`
		sbot.publish({
			type: 'contact',
			following: true,
			contact: %q
		}, (err, followmsg) => {
			t.error(err)
			run()
var did = false
			sbot.on('rpc:connect', rpc => rpc.on('closed', () => {
				if (did) return
				did = true
				setTimeout(() => {
					sbot.connect(%q, (err) => {
						t.error(err)
						setTimeout(exit,2000)
						// exit()
					}) 
				},3000)
			}))
				
			setTimeout(function() { // wait a moment to sync (the address)
					sbot.peerInvites.create({}, (err, invite) => {
						t.error(err)
			
						var fs = require('fs')
						fs.writeFile('invite.txt', invite, (err) => {  
							// throws an error, you could also catch it here
							if (err) throw err;
							
							// success case, the file was saved
							console.warn('invite saved!');
						});
					})
			}, 2000)
		})
	`, bob.KeyPair.Id.Ref(), addr)

	alice := ts.startJSBot(createInvite, ``)

	// bob is FRIENDS with alice (and thus replicating her invites)
	newSeq, err := bob.PublishLog.Append(map[string]interface{}{
		"type":      "contact",
		"contact":   alice.Ref(),
		"following": true,
	})
	r.NoError(err, "failed to publish contact message")
	r.NotNil(newSeq)

	time.Sleep(4 * time.Second)

	// prelim check of invite

	invite, err := ioutil.ReadFile("invite.txt")
	r.NoError(err)
	r.True(bytes.HasPrefix(invite, []byte("inv:")))
	t.Log(string(invite))

	inviteStr := strings.TrimPrefix(string(invite), "inv:")

	invData := strings.Split(inviteStr, ",")

	// use the seed to make a keypair
	seed, err := base64.StdEncoding.DecodeString(invData[0])
	r.NoError(err)
	r.Equal(32, len(seed))
	seedKp, err := ssb.NewKeyPair(bytes.NewReader(seed))
	r.NoError(err)

	// bob has the message
	time.Sleep(4 * time.Second)
	invRef, err := ssb.ParseMessageRef(invData[1])
	r.NoError(err)
	msg, err := bob.Get(*invRef)
	r.NoError(err)

	var rawContent struct {
		Content json.RawMessage
	}
	err = json.Unmarshal(msg.Raw, &rawContent)
	r.NoError(err)

	// can verify the invite message
	enc, err := message.EncodePreserveOrder(rawContent.Content)
	r.NoError(err)
	invmsgWoSig, sig, err := message.ExtractSignature(enc)
	r.NoError(err)

	//  hash("peer-invites:DEVELOPMENT") //XXX DON'T publish without fixing this!
	peerCapData, err := base64.StdEncoding.DecodeString("pmr+IzM+4VAZgi5H5bOopXkwnzqrNussS7DtAJsfbf0=")
	r.NoError(err)

	r.Equal(32, len(peerCapData))
	var peerCap [32]byte
	copy(peerCap[:], peerCapData)

	// t.Log(string(invmsgWoSig))

	mac := auth.Sum(invmsgWoSig, &peerCap)
	err = sig.Verify(mac[:], seedKp.Id)
	r.NoError(err)

	// invite data matches
	var invCore struct {
		Invite *ssb.FeedRef `json:"invite"`
		Host   *ssb.FeedRef `json:"host"`
	}
	err = json.Unmarshal(invmsgWoSig, &invCore)
	r.NoError(err)
	r.Equal(alice.ID, invCore.Host.ID)
	r.Equal(seedKp.Id.ID, invCore.Invite.ID)
	t.Log("invitee key:", seedKp.Id.Ref())

	// 2nd node does it's dance
	before := fmt.Sprintf(`
	var fs = require('fs')
	fs.readFile('invite.txt', 'utf8', (err, invite) => {
		t.error(err)
		t.comment(invite)
		sbot.peerInvites.openInvite(invite, (err, inv_msg, content) => {
			t.error(err)
			console.warn(inv_msg)
			console.warn(content)

			// TODO: check reveal/private?

			sbot.peerInvites.acceptInvite(invite, (err) => {
				t.error(err)
				
				// is now able to connect with its longterm
				run()
			})
		})
	})
	`)

	after := fmt.Sprintf(`aliceFeed = %q // global - pubKey of the first alice
bobFeed = %q
sbot.on('rpc:connect', (rpc) => {
	rpc.on('closed', () => { 
		t.comment('now should have feed:' + aliceFeed)
		pull(
			sbot.createUserStream({id: aliceFeed }),
			pull.collect(function(err, msgs) {
				t.error(err, 'query worked')
				t.equal(2, msgs.length, 'got all the messages')

				checkBob()
			})
		)

		function checkBob() {
			pull(
				sbot.createUserStream({id: bobFeed }),
				pull.collect(function(err, msgs) {
					t.error(err, 'query worked')
					t.equal(4, msgs.length, 'got all the messages')
	console.warn(msgs[3])
					exit()
				})
			)
		}
	})
})
`, alice.Ref(), bob.KeyPair.Id.Ref())

	ts.startJSBot(before, after)

	time.Sleep(10 * time.Second)

	// reuse
	// 2nd node does it's dance
	reuseBefore := fmt.Sprintf(`
	var fs = require('fs')
	fs.readFile('invite.txt', 'utf8', (err, invite) => {
		t.error(err)
		t.comment(invite)
		sbot.peerInvites.openInvite(invite, (err, inv_msg, content) => {
			t.error(err)
			console.warn(inv_msg)
			console.warn(content)

			// should not return spent invite!?

			sbot.peerInvites.acceptInvite(invite, (err) => {
				t.error(err)
				console.warn(err)
				exit()
				
			})
		})
	})
	`)

	ts.startJSBot(reuseBefore, ``)

	<-ts.doneJS
	time.Sleep(10 * time.Second)

	bob.Network.Close()
	bob.Shutdown()
	time.Sleep(5 * time.Second)
	bob.Close()
	ts.wait()
}
