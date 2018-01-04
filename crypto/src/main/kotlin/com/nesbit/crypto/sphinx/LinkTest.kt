package com.nesbit.crypto.sphinx

import com.nesbit.avro.*
import com.nesbit.crypto.DigitalSignature
import com.nesbit.crypto.newSecureRandom
import com.nesbit.crypto.sign
import com.nesbit.crypto.sphinx.IdResponse.Companion.NONCE_SIZE
import com.nesbit.crypto.sphinx.IdResponse.Companion.createNonce
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.SecureRandom
import java.util.*

class IdRequest(val initiatorNonce: ByteArray) : AvroConvertible {
    constructor(idRequestRecord: GenericRecord) :
            this(idRequestRecord.getTyped<ByteArray>("initiatorNonce"))

    constructor(secureRandom: SecureRandom = newSecureRandom()) :
            this(createNonce(secureRandom))

    init {
        require(initiatorNonce.size == NONCE_SIZE) { "Nonce should be $NONCE_SIZE secure random bytes" }
    }

    companion object {
        val idRequestSchema: Schema = Schema.Parser().
                addTypes(mapOf(SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema)).
                parse(IdRequest::class.java.getResourceAsStream("/com/nesbit/crypto/sphinx/idrequest.avsc"))

        fun deserialize(bytes: ByteArray): IdRequest {
            val idRequestRecord = idRequestSchema.deserialize(bytes)
            return IdRequest(idRequestRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(idRequestSchema)
        signatureRecord.putTyped("initiatorNonce", initiatorNonce)
        return signatureRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IdRequest

        if (!Arrays.equals(initiatorNonce, other.initiatorNonce)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(initiatorNonce)
    }
}

class IdResponse(val responderNonce: ByteArray,
                 val initiatorNonce: ByteArray,
                 val replyIdentity: SphinxPublicIdentity,
                 val signatureAlgorithm: String,
                 val signature: ByteArray) : AvroConvertible {
    constructor(idResponseRecord: GenericRecord) :
            this(idResponseRecord.getTyped("responderNonce"),
                    idResponseRecord.getTyped("initiatorNonce"),
                    idResponseRecord.getTyped("replyIdentity", ::SphinxPublicIdentity),
                    idResponseRecord.getTyped("signatureAlgorithm"),
                    idResponseRecord.getTyped("signature"))

    companion object {
        val idResponseSchema: Schema = Schema.Parser().
                addTypes(mapOf(SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema)).
                parse(IdResponse::class.java.getResourceAsStream("/com/nesbit/crypto/sphinx/idresponse.avsc"))

        private val SIGNATURE_PLACEHOLDER = "PRESIGN".toByteArray(Charsets.UTF_8)
        const val NONCE_SIZE = 16

        fun deserialize(bytes: ByteArray): IdResponse {
            val idResponseRecord = idResponseSchema.deserialize(bytes)
            return IdResponse(idResponseRecord)
        }

        fun createNonce(secureRandom: SecureRandom): ByteArray {
            val nonce = ByteArray(NONCE_SIZE)
            secureRandom.nextBytes(nonce)
            return nonce
        }

        fun createSignedResponse(request: IdRequest, localKeys: SphinxIdentityKeyPair, secureRandom: SecureRandom = newSecureRandom()): IdResponse {
            require(request.initiatorNonce.size == NONCE_SIZE) { "Invalid Nonces" }
            val responderNonce = createNonce(secureRandom)
            val testSig = localKeys.signingKeys.sign(ByteArray(0))
            val dummyResponse = IdResponse(responderNonce,
                    request.initiatorNonce,
                    localKeys.public,
                    testSig.signatureAlgorithm,
                    SIGNATURE_PLACEHOLDER)
            val signedData = dummyResponse.serialize()
            val signed = localKeys.signingKeys.sign(signedData)
            return IdResponse(responderNonce,
                    request.initiatorNonce,
                    localKeys.public,
                    signed.signatureAlgorithm,
                    signed.signature)
        }
    }

    fun verifyReponse(request: IdRequest) {
        require(responderNonce.size == NONCE_SIZE && initiatorNonce.size == NONCE_SIZE) { "Invalid Nonces" }
        require(Arrays.equals(request.initiatorNonce, initiatorNonce)) { "Nonce mismatch" }
        val signed = DigitalSignature(signatureAlgorithm, signature, replyIdentity.signingPublicKey)
        val dummyResponse = IdResponse(responderNonce,
                initiatorNonce,
                replyIdentity,
                signatureAlgorithm,
                SIGNATURE_PLACEHOLDER)
        signed.verify(dummyResponse.serialize())
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(idResponseSchema)
        signatureRecord.putTyped("responderNonce", responderNonce)
        signatureRecord.putTyped("initiatorNonce", initiatorNonce)
        signatureRecord.putTyped("replyIdentity", replyIdentity.toGenericRecord())
        signatureRecord.putTyped("signatureAlgorithm", signatureAlgorithm)
        signatureRecord.putTyped("signature", signature)
        return signatureRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IdResponse

        if (!Arrays.equals(responderNonce, other.responderNonce)) return false
        if (!Arrays.equals(initiatorNonce, other.initiatorNonce)) return false
        if (replyIdentity != other.replyIdentity) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!Arrays.equals(signature, other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Arrays.hashCode(responderNonce)
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        result = 31 * result + replyIdentity.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + Arrays.hashCode(signature)
        return result
    }
}