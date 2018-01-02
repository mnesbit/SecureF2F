package com.nesbit.crypto

import com.nesbit.avro.serialize
import com.nesbit.crypto.sphinx.*
import org.junit.Test
import java.security.SignatureException
import kotlin.experimental.xor
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class LinkTestTests {
    @Test
    fun `Hello Serialization Roundtrip`() {
        val id = SphinxIdentityKeyPair.generateKeyPair()
        val helloPacket = Hello(id.public)
        val serialized = helloPacket.serialize()
        val helloPacket2 = Hello.deserialize(serialized)
        assertEquals(helloPacket, helloPacket2)
        val record = helloPacket.toGenericRecord()
        val helloPacket3 = Hello(record)
        assertEquals(helloPacket, helloPacket3)
    }

    @Test
    fun `HelloAck Serialization Roundtrip`() {
        val secureRandom = newSecureRandom()
        val id = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val helloAckPacket = HelloAck(id.public, secureRandom)
        val serialized = helloAckPacket.serialize()
        val helloAckPacket2 = HelloAck.deserialize(serialized)
        assertEquals(helloAckPacket, helloAckPacket2)
        val record = helloAckPacket.toGenericRecord()
        val helloAckPacket3 = HelloAck(record)
        assertEquals(helloAckPacket, helloAckPacket3)
    }

    @Test
    fun `IdRequest Serialization Roundtrip`() {
        val secureRandom = newSecureRandom()
        val id = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val idRequestPacket = IdRequest(id.public, secureRandom)
        val serialized = idRequestPacket.serialize()
        val idRequestPacket2 = IdRequest.deserialize(serialized)
        assertEquals(idRequestPacket, idRequestPacket2)
        val record = idRequestPacket.toGenericRecord()
        val idRequestPacket3 = IdRequest(record)
        assertEquals(idRequestPacket, idRequestPacket3)
    }

    @Test
    fun `IdResponse Serialization Roundtrip`() {
        val secureRandom = newSecureRandom()
        val id = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val id2 = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val nonce1 = ByteArray(16)
        secureRandom.nextBytes(nonce1)
        val nonce2 = ByteArray(16)
        secureRandom.nextBytes(nonce2)
        val idResponsePacket = IdResponse(id.public, nonce1, nonce2, id2.public, "Test".toByteArray())
        val serialized = idResponsePacket.serialize()
        val idResponsePacket2 = IdResponse.deserialize(serialized)
        assertEquals(idResponsePacket, idResponsePacket2)
        val record = idResponsePacket.toGenericRecord()
        val idResponsePacket3 = IdResponse(record)
        assertEquals(idResponsePacket, idResponsePacket3)
    }

    @Test
    fun `IdResponse Construction and signing`() {
        val secureRandom = newSecureRandom()
        val id = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val id2 = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val nonce1 = ByteArray(16)
        secureRandom.nextBytes(nonce1)
        val nonce2 = ByteArray(16)
        secureRandom.nextBytes(nonce2)
        val helloAck = HelloAck(id.public, nonce1)
        val request = IdRequest(id.public, nonce2)
        val signedResponse = IdResponse.createSignedResponse(helloAck, request, id2)
        val serialisedResponse = signedResponse.serialize()
        val receivedResponse = IdResponse.deserialize(serialisedResponse)
        receivedResponse.verifyReponse(helloAck, request)
        receivedResponse.remoteNonce[0] = receivedResponse.remoteNonce[0] xor 1
        helloAck.remoteNonce[0] = helloAck.remoteNonce[0] xor 1
        assertFailsWith<SignatureException> {
            receivedResponse.verifyReponse(helloAck, request)
        }
    }
}