package com.nesbit.crypto

import com.nesbit.avro.serialize
import com.nesbit.crypto.sphinx.IdRequest
import com.nesbit.crypto.sphinx.IdResponse
import com.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import org.junit.Test
import java.security.SignatureException
import kotlin.experimental.xor
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class LinkTestTests {
    @Test
    fun `IdRequest Serialization Roundtrip`() {
        val secureRandom = newSecureRandom()
        val idRequestPacket = IdRequest(secureRandom)
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
        val nonce1 = ByteArray(16)
        secureRandom.nextBytes(nonce1)
        val nonce2 = ByteArray(16)
        secureRandom.nextBytes(nonce2)
        val idResponsePacket = IdResponse(nonce1, nonce2, id.public, "Dummy", "Test".toByteArray())
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
        val nonce1 = ByteArray(16)
        secureRandom.nextBytes(nonce1)
        val request = IdRequest(nonce1)
        val signedResponse = IdResponse.createSignedResponse(request, id)
        val serialisedResponse = signedResponse.serialize()
        val receivedResponse = IdResponse.deserialize(serialisedResponse)
        receivedResponse.verifyReponse(request)
        receivedResponse.responderNonce[0] = receivedResponse.responderNonce[0] xor 1
        assertFailsWith<SignatureException> {
            receivedResponse.verifyReponse(request)
        }
    }
}