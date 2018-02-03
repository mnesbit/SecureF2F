package com.nesbit.crypto.session

import com.nesbit.avro.*
import com.nesbit.crypto.*
import com.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import com.nesbit.crypto.sphinx.VersionedIdentity
import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.KeyPair
import java.security.SignatureException
import java.util.*

class ResponderHelloResponse(val schemaId: SecureHash,
                             val initiatorNonce: ByteArray,
                             val responderNonce: ByteArray,
                             val encryptedPayload: ByteArray) : AvroConvertible {
    constructor(responderHelloResponseRecord: GenericRecord) :
            this(SecureHash("SHA-256", responderHelloResponseRecord.getTyped("schemaFingerprint")),
                    responderHelloResponseRecord.getTyped("initiatorNonce"),
                    responderHelloResponseRecord.getTyped("responderNonce"),
                    responderHelloResponseRecord.getTyped("encryptedPayload"))

    init {
        require(initiatorNonce.size == NONCE_SIZE)
        require(responderNonce.size == NONCE_SIZE)
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
    }

    companion object {
        val responderHelloResponseSchema: Schema = Schema.Parser().addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema)).parse(ResponderHelloResponse::class.java.getResourceAsStream("/com/nesbit/crypto/session/responderhelloresponse.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", responderHelloResponseSchema)

        fun deserialize(bytes: ByteArray): ResponderHelloResponse {
            val responderHelloResponseRecord = responderHelloResponseSchema.deserialize(bytes)
            return ResponderHelloResponse(responderHelloResponseRecord)
        }

        fun createHelloResponse(initiatorInit: InitiatorSessionParams,
                                responderInit: ResponderSessionParams,
                                initiatorHelloRequest: InitiatorHelloRequest,
                                responderSessionKeyPair: KeyPair,
                                responderIdentity: VersionedIdentity,
                                responderSigner: (keyId: SecureHash, toSign: ByteArray) -> DigitalSignatureAndKey): ResponderHelloResponse {
            initiatorHelloRequest.verify(initiatorInit, responderInit, responderSessionKeyPair)
            val sharedState = SessionSecretState(initiatorInit, responderInit, responderSessionKeyPair)
            val sessionBinding = SessionBinding(initiatorInit.initiatorNonce,
                    responderInit.responderNonce,
                    responderInit.responderDHPublicKey,
                    responderIdentity)
            val sessionBindingSignature = responderSigner(responderIdentity.identity.id, sessionBinding.serialize()).toDigitalSignature()
            val identityMAC = getHMAC(sharedState.responseMACKey, responderIdentity.serialize())
            val initiatorProof = SessionIdentityProof(responderIdentity, sessionBindingSignature, identityMAC)
            val payload = initiatorProof.serialize()
            val cipher = ChaCha20Poly1305.Encode(sharedState.responseEncParams)
            val schemaId = SecureHash("SHA-256", schemaFingerprint)
            val encryptedPayload = cipher.encodeCiphertext(payload, concatByteArrays(schemaId.serialize(), initiatorInit.initiatorNonce, responderInit.responderNonce))
            return ResponderHelloResponse(schemaId,
                    initiatorInit.initiatorNonce,
                    responderInit.responderNonce,
                    encryptedPayload)
        }
    }

    fun verify(initiatorInit: InitiatorSessionParams,
               responderInit: ResponderSessionParams,
               initiatorHelloRequest: InitiatorHelloRequest,
               initiatorSessionKeyPair: KeyPair): VersionedIdentity {
        require(Arrays.equals(initiatorNonce, initiatorInit.initiatorNonce)) { "Inconsistent nonces" }
        require(Arrays.equals(responderNonce, responderInit.responderNonce)) { "Inconsistent nonces" }
        initiatorHelloRequest.verify(initiatorInit, responderInit, initiatorSessionKeyPair)
        val sharedState = SessionSecretState(initiatorInit, responderInit, initiatorSessionKeyPair)
        val schemaId = SecureHash("SHA-256", schemaFingerprint)
        val decipher = ChaCha20Poly1305.Decode(sharedState.responseEncParams)
        val decodedPayload = decipher.decodeCiphertext(encryptedPayload, concatByteArrays(schemaId.serialize(), initiatorNonce, responderNonce))
        val initiatorProof = SessionIdentityProof.deserialize(decodedPayload)
        val recreatedSessionBinding = SessionBinding(initiatorNonce,
                responderNonce,
                responderInit.responderDHPublicKey,
                initiatorProof.identityInfo)
        val signedBytes = recreatedSessionBinding.serialize()
        initiatorProof.sessionBindingSignature.verify(initiatorProof.identityInfo.identity.signingPublicKey, signedBytes)
        val recreatedIdentityMAC = getHMAC(sharedState.responseMACKey, initiatorProof.identityInfo.serialize())
        if (recreatedIdentityMAC != initiatorProof.identityMAC) {
            throw SignatureException("Bad identity MAC")
        }
        return initiatorProof.identityInfo
    }

    override fun toGenericRecord(): GenericRecord {
        val responderHelloResponseRecord = GenericData.Record(responderHelloResponseSchema)
        responderHelloResponseRecord.putTyped("schemaFingerprint", schemaFingerprint)
        responderHelloResponseRecord.putTyped("initiatorNonce", initiatorNonce)
        responderHelloResponseRecord.putTyped("responderNonce", responderNonce)
        responderHelloResponseRecord.putTyped("encryptedPayload", encryptedPayload)
        return responderHelloResponseRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ResponderHelloResponse

        if (schemaId != other.schemaId) return false
        if (!Arrays.equals(initiatorNonce, other.initiatorNonce)) return false
        if (!Arrays.equals(responderNonce, other.responderNonce)) return false
        if (!Arrays.equals(encryptedPayload, other.encryptedPayload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        result = 31 * result + Arrays.hashCode(responderNonce)
        result = 31 * result + Arrays.hashCode(encryptedPayload)
        return result
    }

}
