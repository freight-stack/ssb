package gabbygrove

import (
	"bytes"
	"context"
	fmt "fmt"

	"github.com/pkg/errors"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
)

func NewStreamDrain(who *ssb.FeedRef, start margaret.Seq, abs ssb.Message, rl margaret.Log) luigi.Sink {

	return &protoDrain{
		who:       who,
		latestSeq: margaret.BaseSeq(start.Seq()),
		latestMsg: abs,
		rootLog:   rl,
		// hmacSec:   hmac,
	}
}

type protoDrain struct {
	who       *ssb.FeedRef // which feed is pulled
	latestSeq margaret.BaseSeq
	latestMsg ssb.Message
	rootLog   margaret.Log
	// hmacSec   HMACSecret
}

func (ld *protoDrain) Pour(ctx context.Context, v interface{}) error {
	nextMsg, err := ld.verifyAndValidate(ctx, v)
	if err != nil {
		return err
	}

	_, err = ld.rootLog.Append(nextMsg)
	if err != nil {
		return errors.Wrapf(err, "protoStream(%s): failed to append message(%s:%d)", ld.who.Ref(), nextMsg.Key().Ref(), nextMsg.Seq())
	}

	ld.latestSeq = margaret.BaseSeq(nextMsg.Seq())
	ld.latestMsg = nextMsg
	fmt.Println("poured protoDrain", ld.latestSeq)
	return nil
}

func (ld *protoDrain) verifyAndValidate(ctx context.Context, v interface{}) (*MultiMessage, error) {
	trBytes, ok := v.([]uint8)
	if !ok {
		return nil, errors.Errorf("protoStream: expected %T - got %T", trBytes, v)
	}

	var tr Transfer
	err := tr.Unmarshal(trBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "protoStream(%s:%d): transfer unmarshal failed", ld.who.Ref(), ld.latestSeq)
	}

	if !tr.Verify() {
		return nil, errors.Wrapf(err, "protoStream(%s:%d): transfer verify failed", ld.who.Ref(), ld.latestSeq)
	}

	evt, err := tr.getEvent()
	if err != nil {
		return nil, errors.Wrapf(err, "protoStream(%s:%d): event decoding failed", ld.who.Ref(), ld.latestSeq)
	}

	newSeq := tr.Seq()
	if ld.latestSeq.Seq() > 1 {
		if bytes.Compare(ld.latestMsg.Key().Hash, evt.Previous.mr.Hash) != 0 {
			return nil, errors.Errorf("protoStream(%s:%d): previous compare failed expected:%s incoming:%s",
				ld.who.Ref(),
				ld.latestSeq,
				ld.latestMsg.Key().Ref(),
				tr.Key().Ref(),
			)
		}
		if ld.latestMsg.Seq()+1 != newSeq {
			return nil, errors.Errorf("protoStream(%s:%d): next.seq != curr.seq+1", ld.who.Ref(), ld.latestSeq)
		}
	}

	var mm MultiMessage
	mm.key = tr.Key()
	mm.tipe = Proto
	mm.proto = &tr
	return &mm, nil
}

func (ld protoDrain) Close() error {
	fmt.Println("closing protoDrain")
	return nil
}
