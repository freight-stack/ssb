# protochain

This strives to be an easier implementation of https://spec.scuttlebutt.nz/feed/datamodel.html feeds.

It might burrow ideas from https://github.com/AljoschaMeyer/bamboo but want's to avoid bike-shedding by using more common data formats, namly [protobuf](https://developers.google.com/protocol-buffers/) for the message encoding.

Apart from making it easier to implemt this (since the v8 specific JSON quirks go away), the most important improvment over the legacy format is _off-chain content_. This means only the hash of the content is signed and is commited on the chain.

Replication will stay very similar as well, by grouping metadata and content into the _transfer_ struct, omitting the content if it was delete by the remote.

It will also use the same cryptographical primitives ed25519 and sha256.

## Rational for protobuf

It's well known and widely supported on lot's of platforms and languages.

Sharing the protobuf definitions should make it easy to implement creating and validating of these messages.

Using a binary encoding will also save some bytes, making transfer more efficient and should allow storage layers to store more messages with the same amount of bytes.

# Metadata

We borrow most of the fields of the [legacy metadata](https://spec.scuttlebutt.nz/feed/messages.html#metadata).
We do this to reduce churn on the JS stack, like keeping `author` and `timestamp` on each message. 

* `previous`: missing/nil on the first message
* `author`: the pubkey of the feed
* `sequence`: as VarUint
* `content`: a group of three fields: `size`, `type` enum and `hash`
* `timestamp`, like in JS, unix epoch timestamp but in milliseconds. 

This forms the metadata of a message.

The binary encoding produced from this filled structure get's signed with the feeds private key.

# Content

Like stated above, a lot of design decisions here are concessions to the current JS stack.
The overall goal is to add offchain message support while reducing friction on other parts of the stack.
It should be able to present a whole messages in the classical SSB form so that applications don't need to change.

This is also why the `content` portion is encoded as JSON, even though other formats like CBOR might be ablet to do this more efficiently.

Using Protobuf for the whole message would require strictly defining each type of message and is at odds with a free-form database system, where everyone can post new types all the time.

We added a `type` field to the content however to at least give users the option to use other encodings, if wanted and give a way for upgrades.

# References

The hashes and public key references are not base64 encoded readable strings but binary encoded.

We don't plan to support many formats, which is why I decided against something like IPFS Multihash, which supports every hash under the sun. Again, this is not important because we don't encode the `content` with this, just the metadata.

Currently there are only three different reference types:

0x01: ED25519 Public Key, 32bytes of data
0x02: `Previous` message hash, using SHA256 (32bytes of data)
0x03: `Content.Hash` also using SHA256 (32bytes of data)

We add one byte as prefix to those bytes, making all references 33bytes long.

## Development (Go)

to generate the (de)encoder code, install [protoc](https://github.com/google/protobuf) and the [gogoprotobuf tool](https://github.com/gogo/protobuf). Then run this on the message definition file (`message.proto`):

```bash
protoc -I=$HOME/go/src -I=. --gofast_out=. message.proto
```

## Development (JS)

The Go implementation uses gogo's CustomType helper to decode the binary references.
This isn't easyly possible to support cross-platform in a single schema definition file.

The [protobuf.js npm package](https://github.com/protobufjs/protobuf.js) seems to be the most feature complete.

Therefore there is a `jscompat` folder in the tree that shows simple reading and verification of messages.