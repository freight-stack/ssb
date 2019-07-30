'use strict'
var pull         = require('pull-stream')
var pchain = require('/home/cryptix/js-protochain')

exports.name = 'protochain'
exports.version = '1.0.0'
exports.manifest = {
  binaryStream: 'source'
}
exports.permissions = {
    anonymous: {allow: ['binaryStream']},
}


exports.init = function (sbot, config) {
    return {
        verify: pchain.verifyTransfer,
        make: pchain.makeEvent,

        binaryStream: function(args) {
            console.warn("binStream called, crafting some messages")
            console.warn(args)
            // console.warn(arguments)

            let evt1 = pchain.makeEventSync(config.keys, 1, null, {'hello':'world'})
            let evt2 = pchain.makeEventSync(config.keys, 2, evt1.key, {'very':'exciting', 'level':9000})
            let evt3 = pchain.makeEventSync(config.keys, 3, evt2.key, {'last':'message', 'level':9000})

            return pull.values([
                evt1.trBytes,
                evt2.trBytes,
                evt3.trBytes,
            ])
        }
    }
}