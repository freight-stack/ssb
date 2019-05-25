package protochain

import (
	fmt "fmt"
	"sync"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"go.cryptoscope.co/luigi"
	"go.cryptoscope.co/margaret"
	"go.cryptoscope.co/margaret/multilog"
	"go.cryptoscope.co/ssb"
)

type publish struct {
	lock      sync.Mutex
	store     margaret.Log
	authorLog margaret.Log
	enc       *protoEnc
}

func NewPublisher(store margaret.Log, userFeeds multilog.MultiLog, author *ssb.KeyPair) (ssb.Publisher, error) {
	authorLog, err := userFeeds.Get(author.Id.StoredAddr())
	if err != nil {
		// TODO: would be nicer if these could be appended into, then we just have to pass that in as a log
		return nil, errors.Wrap(err, "failed to get userFeeds sublog")
	}
	p := &publish{
		store:     store,
		enc:       NewEncoder(author),
		authorLog: authorLog,
	}
	return p, nil
}

func (p *publish) Seq() luigi.Observable {
	fmt.Println("warning: should return userFeeds seq")
	// conflicted if we should pass Indirect(root, userLog) as store
	return p.authorLog.Seq()
}

func (p *publish) Query(...margaret.QuerySpec) (luigi.Source, error) {
	return nil, errors.Errorf("query unsupported - publish is write-only")
}

func (p *publish) Get(s margaret.Seq) (interface{}, error) {
	return nil, errors.Errorf("TODO:get")
}

func (p *publish) Append(content interface{}) (margaret.Seq, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	currSeqV, err := p.authorLog.Seq().Value()
	if err != nil {
		return nil, errors.Wrap(err, "publish: failed to get current sequence")
	}

	currSeq, ok := currSeqV.(margaret.Seq)
	if !ok {
		return nil, errors.Errorf("publish: unsupported sequence type %T", currSeqV)
	}

	// lookup key of current message for next previous field
	var prev *BinaryRef
	if currSeq.Seq() > margaret.SeqEmpty.Seq() {
		rootLogV, err := p.authorLog.Get(currSeq)
		if err != nil {
			return nil, errors.Wrap(err, "publish: failed to get current sequence")
		}
		rootLogSeq, ok := rootLogV.(margaret.Seq)
		if !ok {
			return nil, errors.Errorf("publish: unexpected stored type %T", rootLogV)
		}

		currMsgV, err := p.store.Get(rootLogSeq)
		if err != nil {
			return nil, errors.Wrap(err, "publish: failed to get current message")
		}

		currMsg, ok := currMsgV.(ssb.Message)
		if !ok {
			spew.Dump(currMsgV)
			return nil, errors.Errorf("publish: unexpected stored type %T (root seq: %d)", currMsgV, rootLogSeq.Seq())
		}

		prev, err = fromRef(currMsg.Key())
		if err != nil {
			return nil, errors.Wrap(err, "publish: failed to get key of curent msg")
		}
	}

	// +2 because we want the first message to be 1
	nextSeq := uint64(currSeq.Seq()) + 2
	tr, _, err := p.enc.Encode(nextSeq, prev, content)
	if err != nil {
		return nil, errors.Wrap(err, "publish: failed to encode content")
	}

	// TODO: make multi-message in root append
	// var mm message.MultiMessage
	// mm.tipe = message.Proto
	// mm.proto = tr
	// mm.key = msgRef

	seq, err := p.store.Append(tr)
	if err != nil {
		return nil, errors.Wrap(err, "publish: to store encoded message")
	}
	return seq, nil
}

func (p *publish) Publish(content interface{}) (*ssb.MessageRef, error) {
	seq, err := p.Append(content)
	if err != nil {
		return nil, err
	}

	val, err := p.store.Get(seq)
	if err != nil {
		return nil, errors.Wrap(err, "publish: failed to get new stored message")
	}

	kv, ok := val.(ssb.Message)
	if !ok {
		return nil, errors.Errorf("publish: unsupported keyer %T", val)
	}

	key := kv.Key()
	if key == nil {
		return nil, errors.Errorf("publish: nil key for new message %d", seq.Seq())
	}

	return key, nil
}
