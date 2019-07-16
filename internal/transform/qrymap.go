package transform

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/luigi/mfr"
	"go.cryptoscope.co/ssb/message"
)

type KeyValue struct {
	Message message.Abstract
	Data    []byte
}

func NewKeyValueWrapper(src luigi.Source, wrap bool) luigi.Source {
	return mfr.SourceMap(src, func(ctx context.Context, v interface{}) (interface{}, error) {
		abs, ok := v.(message.Abstract)
		if !ok {
			return nil, errors.Errorf("kvwrap: wrong message type. expected %T - got %T", abs, v)
		}

		if !wrap {
			return &KeyValue{
				Message: abs,
				Data:    abs.ValueContentJSON(),
			}, nil
		}

		var kv message.KeyValueRaw
		kv.Key = abs.GetKey()
		kv.Value = abs.ValueContentJSON()
		// kv.Timestamp = storedMsg.Timestamp.UnixNano() / 1000000
		kvMsg, err := json.Marshal(kv)
		if err != nil {
			return nil, errors.Wrapf(err, "kvwrap: failed to k:v map message")
		}
		return &KeyValue{
			Message: abs,
			Data:    kvMsg,
		}, nil

	})
}
