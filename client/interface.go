package client

import (
	"io"

	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/muxrpc"

	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message"
)

// TODO: should probably all have contexts? (or at least the client)
type Interface interface {
	muxrpc.Endpoint
	io.Closer
	Whoami() (*ssb.FeedRef, error)

	// ssb.BlobStore
	BlobsWant(ssb.BlobRef) error
	BlobsGet(ref *ssb.BlobRef) (io.Reader, error)

	// names / abouts

	NamesGet() (*NamesGetResult, error)
	NamesSignifier(ref ssb.FeedRef) (string, error)
	NamesImageFor(fr ssb.FeedRef) (*ssb.BlobRef, error)

	Publish(interface{}) (*ssb.MessageRef, error)

	PrivatePublish(interface{}, ...*ssb.FeedRef) (*ssb.MessageRef, error)
	PrivateRead() (luigi.Source, error)

	// MessagesByTypes(string) (luigi.Source, error)
	CreateLogStream(message.CreateHistArgs) (luigi.Source, error)
	CreateHistoryStream(opts message.CreateHistArgs) (luigi.Source, error)
	Tangles(ssb.MessageRef, message.CreateHistArgs) (luigi.Source, error)

	ReplicateUpTo() (luigi.Source, error)
}
