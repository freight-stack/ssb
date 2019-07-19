package message

import (
	"io"

	"go.cryptoscope.co/ssb"

	"github.com/pkg/errors"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb/message/gabbygrove"
	"go.cryptoscope.co/ssb/message/legacy"
)

func NewWrappedLog(in margaret.Log) *WrappedLog {
	return &WrappedLog{Log: in}
}

var _ margaret.Log = (*WrappedLog)(nil)

type WrappedLog struct {
	margaret.Log
}

func (wl WrappedLog) Append(val interface{}) (margaret.Seq, error) {
	var mm MultiMessage

	abs, ok := val.(ssb.Message)
	if !ok {
		return margaret.SeqEmpty, errors.Errorf("wrappedLog: not a ssb.Message: %T", val)
	}

	mm.key = abs.Key()

	switch tv := val.(type) {
	case *legacy.StoredMessage:
		mm.tipe = Legacy
		mm.legacy = tv

	case *gabbygrove.Transfer:
		mm.tipe = Proto
		mm.proto = tv

	default:
		return margaret.SeqEmpty, errors.Errorf("wrappedLog: unsupported message type: %T", val)
	}

	return wl.Log.Append(mm)
}

func (wl WrappedLog) Close() error {
	if clo, ok := wl.Log.(io.Closer); ok {
		return clo.Close()
	}
	return nil
}
