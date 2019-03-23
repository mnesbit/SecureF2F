package uk.co.nesbit.crypto.session

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import java.security.KeyPair
import java.security.SignatureException
import java.util.*

// Third packet in IKEv2 type handshake as described in: 'SIGMA: the `SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and its Use in the IKE Protocols'
// See http://webee.technion.ac.il/~hugo/sigma-pdf.pdf 'Full Fledge' Protocol
class InitiatorHelloRequest private constructor(private val schemaId: SecureHash,
                                                private val initiatorNonce: ByteArray,
                                                private val responderNonce: ByteArray,
                                                private val encryptedPayload: ByteArray) : AvroConvertible {
    constructor(initiatorHelloRequestRecord: GenericRecord) :
            this(SecureHash("SHA-256", initiatorHelloRequestRecord.getTyped("schemaFingerprint")),
                    initiatorHelloRequestRecord.getTyped("initiatorNonce"),
                    initiatorHelloRequestRecord.getTyped("responderNonce"),
                    initiatorHelloRequestRecord.getTyped("encryptedPayload"))
    init {
        require(initiatorNonce.size == NONCE_SIZE)
        require(responderNonce.size == NONCE_SIZE)
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val initiatorHelloRequestSchema: Schema = Schema.Parser()
            .addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/session/initiatorhellorequest.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", initiatorHelloRequestSchema)

        fun deserialize(bytes: ByteArray): InitiatorHelloRequest {
            val initiatorHelloRequestRecord = initiatorHelloRequestSchema.deserialize(bytes)
            return InitiatorHelloRequest(initiatorHelloRequestRecord)
        }

        fun createHelloRequest(initiatorInit: InitiatorSessionParams,
                               responderInit: ResponderSessionParams,
                               initiatorSessionKeyPair: KeyPair,
                               initiatorIdentity: VersionedIdentity,
                               initiatorSigner: (keyId: SecureHash, toSign: ByteArray) -> DigitalSignatureAndKey): InitiatorHelloRequest {
            responderInit.verify(initiatorInit)
            val sharedState = SessionSecretState(initiatorInit, responderInit, initiatorSessionKeyPair)
            val sessionBinding = SessionBinding(initiatorInit.protocolVersion,
                    responderInit.responderNonce,
                    initiatorInit.initiatorNonce,
                    initiatorInit.initiatorDHPublicKey,
                    initiatorIdentity)
            val sessionBindingSignature = initiatorSigner(initiatorIdentity.id, sessionBinding.serialize()).toDigitalSignature()
            val identityMAC = getHMAC(sharedState.requestMACKey, initiatorIdentity.serialize())
            val initiatorProof = SessionIdentityProof(initiatorIdentity, sessionBindingSignature, identityMAC)
            val payload = initiatorProof.serialize()
            val cipher = ChaCha20Poly1305.Encode(sharedState.requestEncParams)
            val schemaId = SecureHash("SHA-256", schemaFingerprint)
            val encryptedPayload = cipher.encodeCiphertext(payload, concatByteArrays(schemaId.serialize(), initiatorInit.initiatorNonce, responderInit.responderNonce))
            return InitiatorHelloRequest(schemaId,
                    initiatorInit.initiatorNonce,
                    responderInit.responderNonce,
                    encryptedPayload)
        }
    }

    fun verify(initiatorInit: InitiatorSessionParams,
               responderInit: ResponderSessionParams,
               responderSessionKeyPair: KeyPair): VersionedIdentity {
        require(initiatorNonce.size == NONCE_SIZE)
        require(responderNonce.size == NONCE_SIZE)
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorNonce, initiatorInit.initiatorNonce)) { "Inconsistent nonces" }
        require(org.bouncycastle.util.Arrays.constantTimeAreEqual(responderNonce, responderInit.responderNonce)) { "Inconsistent nonces" }
        responderInit.verify(initiatorInit)
        val sharedState = SessionSecretState(initiatorInit, responderInit, responderSessionKeyPair)
        val schemaId = SecureHash("SHA-256", schemaFingerprint)
        val decipher = ChaCha20Poly1305.Decode(sharedState.requestEncParams)
        val decodedPayload = decipher.decodeCiphertext(encryptedPayload, concatByteArrays(schemaId.serialize(), initiatorNonce, responderNonce))
        val initiatorProof = SessionIdentityProof.deserialize(decodedPayload)
        val recreatedSessionBinding = SessionBinding(initiatorInit.protocolVersion,
                responderNonce,
                initiatorNonce,
                initiatorInit.initiatorDHPublicKey,
                initiatorProof.identityInfo)
        val signedBytes = recreatedSessionBinding.serialize()
        initiatorProof.sessionBindingSignature.verify(initiatorProof.identityInfo.identity.signingPublicKey, signedBytes)
        val recreatedIdentityMAC = getHMAC(sharedState.requestMACKey, initiatorProof.identityInfo.serialize())
        if (recreatedIdentityMAC != initiatorProof.identityMAC) {
            throw SignatureException("Bad identity MAC")
        }
        return initiatorProof.identityInfo
    }

    override fun toGenericRecord(): GenericRecord {
        val initiatorHelloRequestRecord = GenericData.Record(initiatorHelloRequestSchema)
        initiatorHelloRequestRecord.putTyped("schemaFingerprint", schemaFingerprint)
        initiatorHelloRequestRecord.putTyped("initiatorNonce", initiatorNonce)
        initiatorHelloRequestRecord.putTyped("responderNonce", responderNonce)
        initiatorHelloRequestRecord.putTyped("encryptedPayload", encryptedPayload)
        return initiatorHelloRequestRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InitiatorHelloRequest

        if (schemaId != other.schemaId) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorNonce, other.initiatorNonce)) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(responderNonce, other.responderNonce)) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(encryptedPayload, other.encryptedPayload)) return false

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
