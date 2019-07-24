package message

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/ssb"
	"go.cryptoscope.co/ssb/message/gabbygrove"
	"go.cryptoscope.co/ssb/message/legacy"
	"go.cryptoscope.co/ssb/message/protochain"
)

// NewVerifySink returns a sink that does message verification and appends corret messages to the passed log.
// it has to be used on a feed by feed bases, the feed format is decided by the passed feed reference.
// TODO: start and abs could be the same parameter
// TODO: needs configuration for hmac and what not..
// => maybe construct those from a (global) ref register where all the suffixes live with their corresponding network configuration?
func NewVerifySink(who *ssb.FeedRef, start margaret.Seq, abs ssb.Message, rl margaret.Log) luigi.Sink {

	sd := &streamDrain{
		who:       who,
		latestSeq: margaret.BaseSeq(start.Seq()),
		latestMsg: abs,
		rootLog:   rl,
		// hmacSec:   hmac,
	}
	switch who.Algo {
	case ssb.RefAlgoEd25519:
		sd.verify = legacyVerify
	case ssb.RefAlgoProto:
		sd.verify = protoVerify
	case ssb.RefAlgoGabby:
		sd.verify = gabbyVerify
	}
	return sd
}

type verifyFn func(ctx context.Context, v interface{}) (ssb.Message, error)

func legacyVerify(ctx context.Context, v interface{}) (ssb.Message, error) {
	rmsg, ok := v.(json.RawMessage)
	if !ok {
		return nil, errors.Errorf("legacyVerify: expected %T - got %T", rmsg, v)
	}
	ref, dmsg, err := legacy.Verify(rmsg, nil) // TODO: ld.hmacSec)
	if err != nil {
		return nil, err
	}

	return &legacy.StoredMessage{
		Author_:    &dmsg.Author,
		Previous_:  dmsg.Previous,
		Key_:       ref,
		Sequence_:  dmsg.Sequence,
		Timestamp_: time.Now(),
		Raw_:       rmsg,
	}, nil
}

func protoVerify(ctx context.Context, v interface{}) (ssb.Message, error) {
	trBytes, ok := v.([]uint8)
	if !ok {
		return nil, errors.Errorf("protoVerify: expected %T - got %T", trBytes, v)
	}
	var tr protochain.Transfer
	err := tr.Unmarshal(trBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "protoVerify: transfer unmarshal failed")
	}
	if !tr.Verify() {
		return nil, errors.Wrapf(err, "protoVerify: transfer verify failed")
	}
	return &tr, nil
}

func gabbyVerify(ctx context.Context, v interface{}) (ssb.Message, error) {
	trBytes, ok := v.([]uint8)
	if !ok {
		return nil, errors.Errorf("gabbyVerify: expected %T - got %T", trBytes, v)
	}
	var tr gabbygrove.Transfer
	err := tr.UnmarshalCBOR(trBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "gabbyVerify: transfer unmarshal failed")
	}
	if !tr.Verify() {
		return nil, errors.Wrapf(err, "gabbyVerify: transfer verify failed")
	}
	return &tr, nil
}

type streamDrain struct {
	// gets the input from the screen and returns the next decoded message, if it is valid
	verify verifyFn

	who *ssb.FeedRef // which feed is pulled

	// holds onto the current/newest method (for sequence check and prev hash compare)
	latestSeq margaret.BaseSeq
	latestMsg ssb.Message

	rootLog margaret.Log
	// hmacSec   HMACSecret
}

func (ld *streamDrain) Pour(ctx context.Context, v interface{}) error {
	next, err := ld.verify(ctx, v)
	if err != nil {
		return errors.Wrapf(err, "muxDrain(%s:%d)", ld.who.Ref(), ld.latestSeq.Seq())
	}

	err = ValidateNext(ld.latestMsg, next)
	if err != nil {
		return err
	}

	_, err = ld.rootLog.Append(next)
	if err != nil {
		return errors.Wrapf(err, "muxDrain(%s): failed to append message(%s:%d)", ld.who.Ref(), next.Key().Ref(), next.Seq())
	}

	ld.latestSeq = margaret.BaseSeq(next.Seq())
	ld.latestMsg = next
	return nil
}

func (ld streamDrain) Close() error {
	fmt.Println("closing protoDrain")
	return nil
}

// ValidateNext checks the author stays the same across the feed,
// that he previous hash is correct and that the sequence number is increasing correctly
// TODO: move all the message's publish and drains to it's own package
func ValidateNext(current, next ssb.Message) error {
	if current != nil {
		author := current.Author()

		if !author.Equal(next.Author()) {
			return errors.Errorf("ValidateNext(%s:%d): wrong author: %s", author.Ref(), current.Seq(), next.Author().Ref())
		}

		if bytes.Compare(current.Key().Hash, next.Previous().Hash) != 0 {
			return errors.Errorf("ValidateNext(%s:%d): previous compare failed expected:%s incoming:%s",
				author.Ref(),
				current.Seq(),
				current.Key().Ref(),
				next.Previous().Ref(),
			)
		}
		if current.Seq()+1 != next.Seq() {
			return errors.Errorf("ValidateNext(%s:%d): next.seq != curr.seq+1", author.Ref(), current.Seq())
		}

	} else { // first message
		if next.Seq() != 1 {
			return errors.Errorf("ValidateNext(%s:%d): first message has to have sequence 1", next.Author().Ref(), next.Seq())
		}
	}

	return nil
}
