package com.nesbit.crypto.sphinx

class Hello(val initiatorID: SphinxPublicIdentity)

class HelloAck(val initiatorID: SphinxPublicIdentity, val remoteNonce: ByteArray)

class IdRequest(val initiatorID: SphinxPublicIdentity, val initiatorNonce: ByteArray)

class IdResponse(val initiatorID: SphinxPublicIdentity, val initiatorNonce: ByteArray, val remoteNonce: ByteArray, val replyIdentity: SphinxPublicIdentity, val signature: ByteArray)