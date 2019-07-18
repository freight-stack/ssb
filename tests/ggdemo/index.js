'use strict'
var LayeredGraph = require('layered-graph')
var pull         = require('pull-stream')
var pCont        = require('pull-cont/source')

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
        binaryStream: function() {
            console.dir(arguments)
            return pull(
                pull.values([
                    Buffer.from("daed", 'hex'),
                    Buffer.from("beef", 'hex'),
                    Buffer.from("acab", 'hex'),
                ])
            )
        }
    }
}