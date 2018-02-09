package uk.co.nesbit.crypto

import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.session.InitiatorHelloRequest
import uk.co.nesbit.crypto.session.InitiatorSessionParams
import uk.co.nesbit.crypto.session.ResponderHelloResponse
import uk.co.nesbit.crypto.session.ResponderSessionParams
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import org.junit.Assert.assertEquals
import org.junit.Test

class LinkTestTests {
    @Test
    fun `InitiatorSessionParams Serialization Roundtrip`() {
        val secureRandom = newSecureRandom()
        val (_, initiatorSessionParams) = InitiatorSessionParams.createInitiatorSession(secureRandom)
        val serialized = initiatorSessionParams.serialize()
        val initiatorSessionParams2 = InitiatorSessionParams.deserialize(serialized)
        assertEquals(initiatorSessionParams, initiatorSessionParams2)
        val record = initiatorSessionParams.toGenericRecord()
        val initiatorSessionParams3 = InitiatorSessionParams(record)
        assertEquals(initiatorSessionParams, initiatorSessionParams3)
    }

    @Test
    fun `ResponderSessionParams Serialization Roundtrip`() {
        val secureRandom = newSecureRandom()
        val (_, initiatorSessionParams) = InitiatorSessionParams.createInitiatorSession(secureRandom)
        val (_, responderSessionParams) = ResponderSessionParams.createResponderSession(initiatorSessionParams, secureRandom)
        val serialized = responderSessionParams.serialize()
        val responderSessionParams2 = ResponderSessionParams.deserialize(serialized)
        assertEquals(responderSessionParams, responderSessionParams2)
        val record = responderSessionParams.toGenericRecord()
        val responderSessionParams3 = ResponderSessionParams(record)
        assertEquals(responderSessionParams, responderSessionParams3)
    }

    @Test
    fun `SessionBinding formation and serialize`() {
        val secureRandom = newSecureRandom()
        val initiatorIdentity = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val initiatorVersionedIdentity = initiatorIdentity.getVersionedId(2)
        val (initiatorKeys, initiatorSessionParams) = InitiatorSessionParams.createInitiatorSession(secureRandom)
        val (responderKeys, responderSessionParams) = ResponderSessionParams.createResponderSession(initiatorSessionParams, secureRandom)
        val initiatorHelloRequest = InitiatorHelloRequest.createHelloRequest(initiatorSessionParams,
                responderSessionParams,
                initiatorKeys,
                initiatorVersionedIdentity,
                { _, bytes -> initiatorIdentity.signingKeys.sign(bytes) })
        val serialized = initiatorHelloRequest.serialize()
        val helloRequestDeserialized = InitiatorHelloRequest.deserialize(serialized)
        assertEquals(initiatorHelloRequest, helloRequestDeserialized)
        val helloRequestRecord = initiatorHelloRequest.toGenericRecord()
        val helloRequestDeserialized2 = InitiatorHelloRequest(helloRequestRecord)
        assertEquals(initiatorHelloRequest, helloRequestDeserialized2)
        val receivedIdentity = helloRequestDeserialized.verify(initiatorSessionParams, responderSessionParams, responderKeys)
        assertEquals(initiatorVersionedIdentity, receivedIdentity)
    }

    @Test
    fun `SessionBinding2 formation and serialize`() {
        val secureRandom = newSecureRandom()
        val initiatorIdentity = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val initiatorVersionedIdentity = initiatorIdentity.getVersionedId(2)
        val (initiatorKeys, initiatorSessionParams) = InitiatorSessionParams.createInitiatorSession(secureRandom)
        val (responderKeys, responderSessionParams) = ResponderSessionParams.createResponderSession(initiatorSessionParams, secureRandom)
        val initiatorHelloRequest = InitiatorHelloRequest.createHelloRequest(initiatorSessionParams,
                responderSessionParams,
                initiatorKeys,
                initiatorVersionedIdentity,
                { _, bytes -> initiatorIdentity.signingKeys.sign(bytes) })
        val responderIdentity = SphinxIdentityKeyPair.generateKeyPair(secureRandom)
        val responderVersionedIdentity = responderIdentity.getVersionedId(4)
        val responderHelloResponse = ResponderHelloResponse.createHelloResponse(initiatorSessionParams,
                responderSessionParams,
                initiatorHelloRequest,
                responderKeys,
                responderVersionedIdentity,
                { _, bytes -> responderIdentity.signingKeys.sign(bytes) })
        val serialized = responderHelloResponse.serialize()
        val helloResponseDeserialized = ResponderHelloResponse.deserialize(serialized)
        assertEquals(responderHelloResponse, helloResponseDeserialized)
        val helloResponseRecord = responderHelloResponse.toGenericRecord()
        val helloResponseDeserialized2 = ResponderHelloResponse(helloResponseRecord)
        assertEquals(responderHelloResponse, helloResponseDeserialized2)
        val receivedIdentity = helloResponseDeserialized.verify(initiatorSessionParams, responderSessionParams, initiatorHelloRequest, initiatorKeys)
        assertEquals(responderVersionedIdentity, receivedIdentity)
    }
}