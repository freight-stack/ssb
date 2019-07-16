package protochain

import (
	"context"
	"fmt"
	"sync"

	"github.com/cryptix/go/logging"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/multilog"
	"go.cryptoscope.co/muxrpc"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/graph"
	"go.cryptoscope.co/ssb/plugins/gossip"
)

type handler struct {
	whoami   *ssb.FeedRef
	rl       margaret.Log
	feedsIdx multilog.MultiLog
	gb       graph.Builder
	Info     logging.Interface

	hmacSec  gossip.HMACSecret
	hopCount int
	promisc  bool // ask for remote feed even if it's not on owns fetch list

	activeLock  sync.Mutex
	activeFetch sync.Map
}

func New(logger logging.Interface, whoami *ssb.FeedRef, rootLog margaret.Log, userFeeds multilog.MultiLog, gb graph.Builder, opts ...interface{}) ssb.Plugin {
	h := &handler{
		whoami:   whoami,
		rl:       rootLog,
		feedsIdx: userFeeds,
		gb:       gb,
		Info:     logger,
	}
	for i, o := range opts {
		switch v := o.(type) {
		case gossip.HopCount:
			h.hopCount = int(v)
		case gossip.HMACSecret:
			h.hmacSec = v
		case gossip.Promisc:
			h.promisc = bool(v)
		default:
			logger.Log("warning", "unhandled option", "i", i, "type", fmt.Sprintf("%T", o))
		}
	}
	if h.hopCount == 0 {
		h.hopCount = 2
	}
	return &plugin{h}
}

func (g *handler) HandleConnect(ctx context.Context, e muxrpc.Endpoint) {
	// outwards pull requests are created by (legacy) gossip plugin
}

func (g *handler) HandleCall(ctx context.Context, req *muxrpc.Request, edp muxrpc.Endpoint) {
	g.Info.Log("debug", "protochain call", "m", req.Method, "args", fmt.Sprintf("%+v", req.Args))
	req.CloseWithError(fmt.Errorf("TODO"))
}
