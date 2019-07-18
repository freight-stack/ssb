# protochain (#offchain-content prosposal v2)

After the [initial](%LrMcs9tqgOMLPGv6mN5Z7YYxRQ8qn0JRhVi++OyOvQo=.sha256) proposal to allow only referencing content by hash on the chain was turned down, I investigated alternative approaches, essentially coming up with a new verification scheme based on a binary protocol.

While I like the ideas of Bamboo, I think it has to much _not invented here_, namely encoding schemes for hash references and variable sized integers. IMHO this shouldn't be the exciting part about a new chain format but to introduce the features it offers compared to the current one. For this proposal that is:

1. Easy to implement (hence the use of [protocol buffers](https://de.wikipedia.org/wiki/Protocol_Buffers))
2. Content is only referenced by hash on the immutable data structure (hence enabling omitting and dropping of content locally) 

I propose the `.proto-v1` suffix for feed references.

Further comments this proposal addresses:

## incrementing on a broken format

The main idea of the first proposal was to add offchain-content without overhauling the verification scheme.
We got numerous comments on this, the gist being that we tried to hard, improving something that should be deprecated altogether.

Therefore we chose a clean slate approach with a new encoding scheme. This comes with the downside of requiring multiple supported _feed types_ in the stack. Personally I think this is good though as it will pave the way for other formats, like bamboo, as well.

## The use of muxprc specific features for transmission/replication

The idea to transmit content and metadata as two muxrpc frames was my idea. It seems sensible/practical because it fitted into the existing stack but I see now that it tried to much to fit into the existing way and hid a dependency along the way.

This is why we have the `transfer` message definition which has two fields. One for the message, which should be required and one field for the content, which can be omitted.

# Rational

While this is would introduce radical new ways of doing things, like requiring protobuf for encoding and supporting multiple feed types, it also makes concessions to how things are currently. In a sense this proposal should be seen as an overhaul of the current scheme, only adding offchain capabilities. Let me elaborate on two of them which cater to this point specifically:

## Keeping the timestamp on the message

In principle, the timestamp is an application concern. Some message types could omit it and it could ne considered _cleaner_ to move them up into the content of the types that want/need them. We recognize however that it would stir up problems for existing applications and this is something we are not interested in.

## Having the author on the message

A similar argument could be made for the author of a message. In the current design the author never changes over the lifetime of a feed, so why have it on each and every message? Especially if you replicate one feed at a time it seems wasteful, since the author is already known.

@dominic made a pretty good security argument [here](%1AsqTRxdVrbfypC69W7uWbMClQteNNnnl3ohzbpu3Xw=.sha256). It should always be known which key-pair created a signature and thus having it reduces ambiguity and possible backdoors.

## Only encoding the content

This format would only encode the metadata as protobuf, leaving the _user_ to encode their content as they see fit.
Since we don't want to cause problems for applications, we suggest keeping the `content` portion in JSON.
This should allow for messages to be mapped full JSON objects which look just like regular messages so that they can be consumed by applications without any change.

For upgrades and more advance uses we added a `encoding enum` that only defines JSON up until now.

# Definitions

If you never worked with protobuf here is gist of what the workflow is like, using the proposed definitions.
One writes `message` definitions which describe the type and ordering of each field.

For the metadata of a message it looks like this:

```protobuf
message Meta {
  bytes previous   = 1;
  bytes author     = 2;
  uint64 sequence  = 3;
  Content content  = 4;
  uint64 timestamp = 5;
}

message Content {
    ContentType type = 1;
    uint64 size = 2;
    bytes hash = 3;
}

enum ContentType {
    Missing = 0;
    JSON = 1;
    // CBOR = 2; ???
}
```

Field one and two are arbitrary byte arrays, named `previous` and `author`.
Field number three is the sequence number of the message. (Protobuf uses variable size integers which grow in bytes as needed.)
Field number four embeds another structure inside of `Meta`, the `content` which in turn is defined as the three fields `type`, `size` and `hash`.
The `ContentType` is an enumeration of possible values for a field, making sure the protocol agrees on a set of known values.

With such a definition file at hand, protobuf toolchains can generate code that does the marshalling to and from bytes for you.
That is also where it's job ends, though. What constitutes a valid hash or public key is up to the implementor of this new feed type. 

The next needed message structure would be `message` which is the meta with the corresponding signature:

```
message Message {
    Meta meta = 1;
    bytes signature = 2;
}
```

To validate a message, the receiver re-encodes just the `meta` fields to bytes and passes it and the signature to the cryptographic function that does the validation.

Lastly, there is a `transfer` message structure that has a `Message` and a byte array for the actual `content`:

```
message Transfer {
    Message Message = 1;
    bytes content = 2;
}
```

# Hash/PubKey References

The hashes and public key references are not base64 encoded readable strings but binary encoded.

We don't plan to support many formats, which is why I decided against something like IPFS Multihash, which supports every hash under the sun. Again, this is not important because we don't encode the `content` with this, just the metadata.

Currently there are only three different reference types:

0x01: ED25519 Public Key, 32bytes of data
0x02: `Previous` message hash, using SHA256 (32bytes of data)
0x03: `Content.Hash` also using SHA256 (32bytes of data)

We add one byte as prefix to those bytes, making all references 33bytes long.


# Code

the current work-in-progress repository can be found here: http://cryptbox.mindeco.de/ssb/protochain

It experiments with Go and javascript interoperability and shows that signature verification and content hashing works as expected.

Integration into go-ssb or the javascript stack is pending on review comments.

One open question would be how to get this into EBT while also supporting the classical/legacy way of encoding messages.
For classical replication I'd suggest a new rpc stream command, similar to `createHistoryStream` which sends `transfer` encoded messages one by one.

# Further comments

First, I'm not heartpressed on the name at all. And if this isn't already obvious, this would become the feed format that verse uses.

## alternative encodings

I'm undecided on protocol buffers, it just seemed to be the most stable (or boring if you like).

Possible interesting alternatives:

* captnproto (seemed like a bit bleeding edge)
* msgpack (could work, seems niche)
* cbor (self-describing isn't really important for the fields we are talking about, everything but content is well defined)

## Deletion requests

I believe we should leave this out of the spec and just give way for clients to drop content as wanted. Tuning replication rules with signed deletions or what ever can be done orthogonal if the chain/feed format allows validation with missing content.

## Size benefits

This cuts down the amount of transmitted bytes considerably. As an example, a _old_ contact message clocks in at roughly 434 bytes (JSON without whitespace, sequence in the hundreds range). Encoding a contact message with this, results in 289 bytes, 119 of which are still JSON. This overhead is small for longer posts but still wanted to mention it. The main driver of this reduction is the binary encoding of the references and being able to omit the field names. Converting content to a binary encoding would reduce it further but as stated above would require strict schemas for every type.

## I'm not sure how long lived this will be

I _think_ this is a solid format but wouldn't mind to be superseded by something else once it surfaces. As a migration path, I'd suggest we double down on `SameAs`.


# Adressed comments

## Names

The hole thing might be called _Gabby Groves_

## Event

_Message_ and _Meta_ were not easy to speak and reason about. _What includes what?_, etc. 

Also `Message` was redundant to begin with. The Hash of a signed event is the SHA256 of `event` and `signature` bytes concataneted.

TODO: cfts msg

## Deterministic encoding

TODO: how sending the signed bytes instead of remarshaling makes it extensible.

