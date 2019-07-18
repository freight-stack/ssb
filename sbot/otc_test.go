package sbot

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cryptix/go/logging/logtest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/internal/mutil"
	"go.cryptoscope.co/ssb/private"
	"go.cryptoscope.co/ssb/message/gabbygrove"
)

func TestOffchainSync(t *testing.T) {
	r := require.New(t)
	// a := assert.New(t)
	ctx := context.TODO()

	os.RemoveAll("testrun")

	aliLog, _ := logtest.KitLogger("ali", t)
	ali, err := New(
		WithInfo(aliLog),
		WithRepoPath(filepath.Join("testrun", t.Name(), "ali")),
		WithListenAddr(":0"))
	r.NoError(err)

	var aliErrc = make(chan error, 1)
	go func() {
		err := ali.Network.Serve(ctx)
		if err != nil {
			aliErrc <- errors.Wrap(err, "ali serve exited")
		}
		close(aliErrc)
	}()

	// bob is the protochain one
	bobsKey, err := ssb.NewKeyPair(nil)
	r.NoError(err)
	bobsKey.Id.Algo = ssb.RefAlgoProto

	bobLog, _ := logtest.KitLogger("bob", t)
	bob, err := New(
		WithKeyPair(bobsKey),
		WithInfo(bobLog),
		WithRepoPath(filepath.Join("testrun", t.Name(), "bob")),
		WithListenAddr(":0"))
	r.NoError(err)

	var bobErrc = make(chan error, 1)
	go func() {
		err := bob.Network.Serve(ctx)
		if err != nil {
			bobErrc <- errors.Wrap(err, "bob serve exited")
		}
		close(bobErrc)
	}()

	// be friends
	seq, err := ali.PublishLog.Append(ssb.Contact{
		Type:      "contact",
		Following: true,
		Contact:   bob.KeyPair.Id,
	})
	r.NoError(err)
	r.Equal(margaret.BaseSeq(0), seq)

	seq, err = bob.PublishLog.Append(ssb.Contact{
		Type:      "contact",
		Following: true,
		Contact:   ali.KeyPair.Id,
	})
	r.NoError(err)

	for i := 0; i < 9; i++ {
		seq, err := bob.PublishLog.Append(map[string]interface{}{
			"test": i,
		})
		r.NoError(err)
		r.Equal(margaret.BaseSeq(i+1), seq)
	}

	// sanity, check bob has his shit together
	bobsOwnLog, err := bob.UserFeeds.Get(bob.KeyPair.Id.StoredAddr())
	r.NoError(err)

	seqv, err := bobsOwnLog.Seq().Value()
	r.NoError(err)
	r.Equal(margaret.BaseSeq(9), seqv, "bob doesn't have his own log!")

	// dial
	err = bob.Network.Connect(ctx, ali.Network.GetListenAddr())
	r.NoError(err)

	// give time to sync
	time.Sleep(3 * time.Second)
	// be done
	ali.Network.GetConnTracker().CloseAll()

	// check that bobs messages got to ali
	bosLogAtAli, err := ali.UserFeeds.Get(bob.KeyPair.Id.StoredAddr())
	r.NoError(err)

	seqv, err = bosLogAtAli.Seq().Value()
	r.NoError(err)
	r.Equal(margaret.BaseSeq(9), seqv)

	src, err := mutil.Indirect(ali.RootLog, bosLogAtAli).Query()
	r.NoError(err)
	for {
		v, err := src.Next(ctx)
		if luigi.IsEOS(err) {
			break
		} else if err != nil {
			r.NoError(err)
		}
		msg, ok := v.(protochain.MultiMessage)
		r.True(ok, "Type: %T", v)
		// t.Log(msg)
		_, err = msg.ByType(protochain.Proto)
		r.NoError(err)
		// a.True(msg.Author.Offchain)
		// a.NotEmpty(msg.Offchain)
	}

	ali.Shutdown()
	bob.Shutdown()
	r.NoError(ali.Close())
	r.NoError(bob.Close())

	r.NoError(<-mergeErrorChans(aliErrc, bobErrc))
}

func TestOffchainPrivate(t *testing.T) {
	r := require.New(t)
	a := assert.New(t)
	ctx := context.TODO()

	os.RemoveAll("testrun")

	aliLog, _ := logtest.KitLogger("ali", t)
	ali, err := New(
		WithInfo(aliLog),
		WithRepoPath(filepath.Join("testrun", t.Name(), "ali")),
		WithListenAddr(":0"))
	r.NoError(err)

	var aliErrc = make(chan error, 1)
	go func() {
		err := ali.Network.Serve(ctx)
		if err != nil {
			aliErrc <- errors.Wrap(err, "ali serve exited")
		}
		close(aliErrc)
	}()

	// bob is the otc one
	bobsKey, err := ssb.NewKeyPair(nil)
	r.NoError(err)
	bobsKey.Id.Algo = ssb.RefAlgoProto

	bobLog, _ := logtest.KitLogger("bob", t)
	bob, err := New(
		WithKeyPair(bobsKey),
		WithInfo(bobLog),
		WithRepoPath(filepath.Join("testrun", t.Name(), "bob")),
		WithListenAddr(":0"))
	r.NoError(err)

	var bobErrc = make(chan error, 1)
	go func() {
		err := bob.Network.Serve(ctx)
		if err != nil {
			bobErrc <- errors.Wrap(err, "bob serve exited")
		}
		close(bobErrc)
	}()

	// be friends
	seq, err := ali.PublishLog.Append(ssb.Contact{
		Type:      "contact",
		Following: true,
		Contact:   bob.KeyPair.Id,
	})
	r.NoError(err)
	r.Equal(margaret.BaseSeq(0), seq)

	seq, err = bob.PublishLog.Append(ssb.Contact{
		Type:      "contact",
		Following: true,
		Contact:   ali.KeyPair.Id,
	})
	r.NoError(err)

	for i := 0; i < 9; i++ {
		jsonMsg, err := json.Marshal(map[string]interface{}{
			"test": i,
		})
		r.NoError(err)
		boxedMsg, err := private.Box(jsonMsg, bobsKey.Id, ali.KeyPair.Id)
		r.NoError(err)

		seq, err := bob.PublishLog.Append(boxedMsg)
		r.NoError(err)
		r.Equal(margaret.BaseSeq(i+1), seq)
	}

	// dial
	err = bob.Network.Connect(ctx, ali.Network.GetListenAddr())
	r.NoError(err)

	time.Sleep(3 * time.Second)

	ali.Network.GetConnTracker().CloseAll()

	bosLogAtAli, err := ali.UserFeeds.Get(bob.KeyPair.Id.StoredAddr())
	r.NoError(err)

	seqv, err := bosLogAtAli.Seq().Value()
	r.NoError(err)
	r.Equal(margaret.BaseSeq(9), seqv) // contact + pms

	src, err := mutil.Indirect(ali.RootLog, bosLogAtAli).Query()
	r.NoError(err)
	i := 0
	for {
		v, err := src.Next(ctx)
		if luigi.IsEOS(err) {
			break
		} else if err != nil {
			r.NoError(err)
		}
		msg, ok := v.(ssb.Message)
		r.True(ok)

		if i == 0 {
			i++
			continue // contact msg
		}

		oc := string(msg.Content())
		t.Log(oc)
		unboxed, err := private.Unbox(ali.KeyPair, oc)
		if !a.NoError(err) {
			i++
			continue
		}
		t.Log(string(unboxed))
		a.NotNil(unboxed)
		var received struct {
			Test int
		}
		err = json.Unmarshal(unboxed, &received)
		a.NoError(err)
		a.Equal(received.Test, i-1) // contact msg
		i++
	}

	privs, err := ali.PrivateLogs.Get(ali.KeyPair.Id.StoredAddr())
	r.NoError(err)

	v, err := privs.Seq().Value()
	r.NoError(err)
	r.Equal(margaret.BaseSeq(8), v) // only pms

	ali.Shutdown()
	bob.Shutdown()
	r.NoError(ali.Close())
	r.NoError(bob.Close())

	r.NoError(<-mergeErrorChans(aliErrc, bobErrc))
}
