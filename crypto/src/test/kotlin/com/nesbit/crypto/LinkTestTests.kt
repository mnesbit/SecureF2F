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
        assertEquals(idRequestPacket, IdRequest.tryDeserialize(serialized))
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
        assertEquals(idResponsePacket, IdResponse.tryDeserialize(serialized))
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

    @Test
    fun `test tryDeserialize on requests`() {
        assertEquals(null, IdRequest.tryDeserialize(ByteArray(0)))
        assertEquals(null, IdRequest.tryDeserialize(ByteArray(47)))
        assertEquals(null, IdRequest.tryDeserialize(ByteArray(48)))
        assertEquals(null, IdRequest.tryDeserialize(ByteArray(49)))
        val request = IdRequest()
        val serialized = request.serialize()
        assertEquals(request, IdRequest.tryDeserialize(serialized))
        assertEquals(null, IdRequest.tryDeserialize(concatByteArrays(ByteArray(1), serialized)))
        assertEquals(null, IdRequest.tryDeserialize(concatByteArrays(serialized, ByteArray(1))))
        for (i in 0 until 32) {// Changes to schema fingerprint fail, changes to nonce are ignored
            for (j in 0 until 8) {
                val mask = (1 shl j).toByte()
                serialized[i] = serialized[i] xor mask
                assertEquals(null, IdRequest.tryDeserialize(serialized))
                serialized[i] = serialized[i] xor mask
            }
        }
    }

    @Test
    fun `test tryDeserialize on responses`() {
        assertEquals(null, IdResponse.tryDeserialize(ByteArray(0)))
        assertEquals(null, IdResponse.tryDeserialize(ByteArray(47)))
        assertEquals(null, IdResponse.tryDeserialize(ByteArray(48)))
        assertEquals(null, IdResponse.tryDeserialize(ByteArray(49)))
        val secureRandom = newSecureRandom()
        val id = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val nonce1 = ByteArray(16)
        secureRandom.nextBytes(nonce1)
        val request = IdRequest(nonce1)
        val signedResponse = IdResponse.createSignedResponse(request, id)
        val serialized = signedResponse.serialize()
        assertEquals(signedResponse, IdResponse.tryDeserialize(serialized))
        assertEquals(null, IdResponse.tryDeserialize(concatByteArrays(ByteArray(1), serialized)))
        assertEquals(null, IdResponse.tryDeserialize(concatByteArrays(serialized, ByteArray(1))))
        for (i in 0 until 32) {// Changes to schema fingerprint fail, changes to nonce are ignored
            for (j in 0 until 8) {
                val mask = (1 shl j).toByte()
                serialized[i] = serialized[i] xor mask
                assertEquals(null, IdResponse.tryDeserialize(serialized))
                serialized[i] = serialized[i] xor mask
            }
        }
    }
}