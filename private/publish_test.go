package private_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.cryptoscope.co/luigi"

	"github.com/cryptix/go/logging/logtest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/client"
	"go.cryptoscope.co/ssb/sbot"
)

func TestPrivatePublish(t *testing.T) {
	t.Run("classic", testPublishPerAlgo(ssb.RefAlgoFeedSSB1))
	t.Run("gabby", testPublishPerAlgo(ssb.RefAlgoFeedGabby))
}

func testPublishPerAlgo(algo string) func(t *testing.T) {
	return func(t *testing.T) {
		r, a := require.New(t), assert.New(t)

		srvRepo := filepath.Join("testrun", t.Name(), "serv")
		os.RemoveAll(srvRepo)

		alice, err := ssb.NewKeyPair(bytes.NewReader(bytes.Repeat([]byte("alice"), 8)))
		r.NoError(err)
		alice.Id.Algo = algo

		// srvLog := log.NewJSONLogger(os.Stderr)
		srvLog, _ := logtest.KitLogger("srv", t)
		srv, err := sbot.New(
			sbot.WithKeyPair(alice),
			sbot.WithInfo(srvLog),
			sbot.WithRepoPath(srvRepo),
			sbot.WithListenAddr(":0"),
			sbot.WithUNIXSocket(),
		)
		r.NoError(err, "sbot srv init failed")

		c, err := client.NewUnix(context.TODO(), filepath.Join(srvRepo, "socket"))
		r.NoError(err, "failed to make client connection")

		type msg struct {
			Type string
			Msg  string
		}
		ref, err := c.PrivatePublish(msg{"test", "hello, world"}, alice.Id)
		r.NoError(err, "failed to publish")
		r.NotNil(ref)

		src, err := c.PrivateRead()
		r.NoError(err, "failed to open private stream")

		v, err := src.Next(context.TODO())
		r.NoError(err, "failed to get msg")

		savedMsg, ok := v.(ssb.Message)
		r.True(ok, "wrong type: %T", v)
		r.Equal(savedMsg.Key().Ref(), ref.Ref())

		v, err = src.Next(context.TODO())
		r.Error(err)
		r.EqualError(luigi.EOS{}, errors.Cause(err).Error())

		// shutdown
		a.NoError(c.Close())
		srv.Shutdown()
		r.NoError(srv.Close())
	}
}