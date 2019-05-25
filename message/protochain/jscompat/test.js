var ssbKeys = require('ssb-keys')

var protobuf = require('protobufjs')
protobuf.load("message.proto", function (err, root) {
    if (err) throw err;

    // Obtain a message type
    var event = root.lookupType("gabbygrove.Event");

    // Create a new message
    var evt1 = {
        sequence: 42,
        timestamp: 0,
        content: {
            type: 1,
        }
    }
    var pbEvent = event.create(evt1); // or use .fromObject if conversion is necessary

    var buffer = event.encode(pbEvent).finish();
    console.log("evt1:", buffer.toString('base64'))

    // create an event from raw bytes
    var decodedEvt = event.decode(buffer);

    var convertOpts = {
        longs: Number,
        enums: String,
        bytes: Buffer,
    }

    var object = event.toObject(decodedEvt, convertOpts);
    console.log("evt1 to obj:")
    console.log(object)

    // example from Writer go test:
    var input = Buffer.from("122101aed3dab65ce9e0d6c50d46fceffb552296ed21b6e0b537a6a0184575ce8f5cbd2227080110071a2103e806ecf2b7c37fb06dc198a9b905be64ee3fdb8237ef80d316acb7c85bbf5f02", "hex")
    var evt2 = event.decode(input)

    var err = event.verify(evt2)
    if (err) throw err

    var obj2 = event.toObject(evt2, convertOpts);
    console.log("evt2 from b64 data:")
    console.log(obj2)

    if (obj2.author.length !== 33) throw new Error("invalid reference length")
    if (obj2.author[0] !== 0x01) throw new Error("not ed25519 ref type")
    var msgAuthor = obj2.author.slice(1)

    // generate key-pair with same seed
    var seed = Buffer.from("dead".repeat(8))
    var testKp = ssbKeys.generate('ed25519', seed)


    var pubBytes = Buffer.from(testKp.public.replace(/\.ed25519$/, ''), 'base64')

    if (!msgAuthor.equals(pubBytes)) {
        console.log(msgAuthor)
        throw new Error("not the test keypair!")
    }

    // transfer decoding
    var transfer = root.lookupType("gabbygrove.Transfer");

    // from go test, msg3 (type:contact spectating:true)
    var trBuf = Buffer.from("0a710a2102bb4ba82ee4180789b937080bd995d00966f3a13bf35785c2af51f480fbcb1cdf1221018a35dfa466b23c247f957d71504c01074653df6a6a831108d015ea894b192203180422270801102a1a210388feb52df7ad32786e8c1e527a75b9b2ad71445752a18eb25481dfc98445422f124071e1eed9f315fcb708bd08cdc86a2e5b2324ad6485979ff81e5390358f83a4ff8da3f5d7fa9f0f3174d6a2bbeeac02746e3372a6ec81e80b0a3aca4bf667c90b1a2a7b22736571223a322c2273706563746174696e67223a747275652c2274797065223a2274657374227d0a", 'hex')
    var transferMsg = transfer.decode(trBuf)
    // console.log(transferMsg)
    var err = transfer.verify(transferMsg)
    if (err) throw err

    var trObj = transfer.toObject(transferMsg, convertOpts);

    var evtFromTr = event.decode(trObj.event)

    // decode JSON from content
    var contentObj = JSON.parse(trObj.content)
    console.log(contentObj)
    // if (contentObj.contact !== testKp.id) throw new Error('wrong contact on message')
    if (!contentObj.spectating) throw new Error('expected spectating field on testmsg')

    // re-create content hash
    console.log('content hash:')
    console.log(ssbKeys.hash(trObj.content))
    console.log(evtFromTr.content.hash.slice(1).toString('base64'))

    var trKeyPair = ssbKeys.generate('ed25519', Buffer.from("beef".repeat(8)))
    var trKeyPairBytes = Buffer.from(trKeyPair.public.replace(/\.ed25519$/, ''), 'base64')

    // ssb-keys only exports signObj and verifyObj
    console.log("signature len:", trObj.signature.length)
    var sodium = require('sodium-native')
    var verified = sodium.crypto_sign_verify_detached(trObj.signature, trObj.event, trKeyPairBytes)
    if (!verified) throw new Error('meta did not verify')
    console.log('verified:', verified)
})