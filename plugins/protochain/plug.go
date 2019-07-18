package gabbygrove

import (
	"go.cryptoscope.co/muxrpc"
)

type plugin struct {
	h muxrpc.Handler
}

func (p plugin) Name() string {
	return "protochain"
}

func (p plugin) Method() muxrpc.Method {
	return muxrpc.Method{"protochain"}
}

func (p plugin) Handler() muxrpc.Handler {
	return p.h
}
