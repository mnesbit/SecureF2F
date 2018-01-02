package com.nesbit.crypto.sphinx

import com.nesbit.avro.*
import com.nesbit.crypto.DigitalSignature
import com.nesbit.crypto.newSecureRandom
import com.nesbit.crypto.sign
import com.nesbit.crypto.sphinx.IdResponse.Companion.NONCE_SIZE
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.SecureRandom
import java.util.*

class Hello(val initiatorIdentity: SphinxPublicIdentity) : AvroConvertible {
    constructor(helloRecord: GenericRecord) :
            this(helloRecord.getTyped("initiatorIdentity", ::SphinxPublicIdentity))

    companion object {
        val helloSchema: Schema = Schema.Parser().
                addTypes(mapOf(SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema)).
                parse(Hello::class.java.getResourceAsStream("/com/nesbit/crypto/sphinx/hello.avsc"))

        fun deserialize(bytes: ByteArray): Hello {
            val helloRecord = helloSchema.deserialize(bytes)
            return Hello(helloRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(helloSchema)
        signatureRecord.putTyped("initiatorIdentity", initiatorIdentity.toGenericRecord())
        return signatureRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Hello

        if (initiatorIdentity != other.initiatorIdentity) return false

        return true
    }

    override fun hashCode(): Int {
        return initiatorIdentity.hashCode()
    }
}

class HelloAck(val initiatorIdentity: SphinxPublicIdentity, val remoteNonce: ByteArray) : AvroConvertible {
    constructor(helloAckRecord: GenericRecord) :
            this(helloAckRecord.getTyped("initiatorIdentity", ::SphinxPublicIdentity),
                    helloAckRecord.getTyped<ByteArray>("remoteNonce"))

    constructor(initiatorIdentity: SphinxPublicIdentity, secureRandom: SecureRandom = newSecureRandom()) :
            this(initiatorIdentity, { val nonce = ByteArray(NONCE_SIZE); secureRandom.nextBytes(nonce); nonce }())

    init {
        require(remoteNonce.size == NONCE_SIZE) { "Nonce should be $NONCE_SIZE secure random bytes" }
    }

    companion object {
        val helloAckSchema: Schema = Schema.Parser().
                addTypes(mapOf(SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema)).
                parse(HelloAck::class.java.getResourceAsStream("/com/nesbit/crypto/sphinx/helloack.avsc"))

        fun deserialize(bytes: ByteArray): HelloAck {
            val helloAckRecord = helloAckSchema.deserialize(bytes)
            return HelloAck(helloAckRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(helloAckSchema)
        signatureRecord.putTyped("initiatorIdentity", initiatorIdentity.toGenericRecord())
        signatureRecord.putTyped("remoteNonce", remoteNonce)
        return signatureRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HelloAck

        if (initiatorIdentity != other.initiatorIdentity) return false
        if (!Arrays.equals(remoteNonce, other.remoteNonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = initiatorIdentity.hashCode()
        result = 31 * result + Arrays.hashCode(remoteNonce)
        return result
    }
}

class IdRequest(val initiatorIdentity: SphinxPublicIdentity, val initiatorNonce: ByteArray) : AvroConvertible {
    constructor(idRequestRecord: GenericRecord) :
            this(idRequestRecord.getTyped("initiatorIdentity", ::SphinxPublicIdentity),
                    idRequestRecord.getTyped<ByteArray>("initiatorNonce"))

    constructor(initiatorIdentity: SphinxPublicIdentity, secureRandom: SecureRandom = newSecureRandom()) :
            this(initiatorIdentity, { val nonce = ByteArray(NONCE_SIZE); secureRandom.nextBytes(nonce); nonce }())

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
        signatureRecord.putTyped("initiatorIdentity", initiatorIdentity.toGenericRecord())
        signatureRecord.putTyped("initiatorNonce", initiatorNonce)
        return signatureRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IdRequest

        if (initiatorIdentity != other.initiatorIdentity) return false
        if (!Arrays.equals(initiatorNonce, other.initiatorNonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = initiatorIdentity.hashCode()
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        return result
    }
}

class IdResponse(val initiatorIdentity: SphinxPublicIdentity,
                 val initiatorNonce: ByteArray,
                 val remoteNonce: ByteArray,
                 val replyIdentity: SphinxPublicIdentity,
                 val signature: ByteArray) : AvroConvertible {
    constructor(idResponseRecord: GenericRecord) :
            this(idResponseRecord.getTyped("initiatorIdentity", ::SphinxPublicIdentity),
                    idResponseRecord.getTyped("initiatorNonce"),
                    idResponseRecord.getTyped("remoteNonce"),
                    idResponseRecord.getTyped("replyIdentity", ::SphinxPublicIdentity),
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

        fun createSignedResponse(originalAck: HelloAck, request: IdRequest, localKeys: SphinxIdentityKeyPair): IdResponse {
            require(originalAck.remoteNonce.size == NONCE_SIZE && request.initiatorNonce.size == NONCE_SIZE) { "Invalid Nonces" }
            require(originalAck.initiatorIdentity == request.initiatorIdentity) { "Identities must match" }
            val dummyResponse = IdResponse(request.initiatorIdentity,
                    request.initiatorNonce,
                    originalAck.remoteNonce,
                    localKeys.public,
                    SIGNATURE_PLACEHOLDER)
            val signedData = dummyResponse.serialize()
            val signed = localKeys.signingKeys.sign(signedData)
            return IdResponse(request.initiatorIdentity,
                    request.initiatorNonce,
                    originalAck.remoteNonce,
                    localKeys.public,
                    signed.signature)
        }
    }

    fun verifyReponse(originalAck: HelloAck, request: IdRequest) {
        require(remoteNonce.size == NONCE_SIZE && initiatorNonce.size == NONCE_SIZE) { "Invalid Nonces" }
        require(originalAck.initiatorIdentity == request.initiatorIdentity && request.initiatorIdentity == initiatorIdentity) { "Identities must match" }
        require(Arrays.equals(originalAck.remoteNonce, remoteNonce) && Arrays.equals(request.initiatorNonce, initiatorNonce)) { "Nonce mismatch" }
        val signed = DigitalSignature("NONEwithEdDSA", signature, replyIdentity.signingPublicKey)
        val dummyResponse = IdResponse(initiatorIdentity,
                initiatorNonce,
                remoteNonce,
                replyIdentity,
                SIGNATURE_PLACEHOLDER)
        signed.verify(dummyResponse.serialize())
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(idResponseSchema)
        signatureRecord.putTyped("initiatorIdentity", initiatorIdentity.toGenericRecord())
        signatureRecord.putTyped("initiatorNonce", initiatorNonce)
        signatureRecord.putTyped("remoteNonce", remoteNonce)
        signatureRecord.putTyped("replyIdentity", replyIdentity.toGenericRecord())
        signatureRecord.putTyped("signature", signature)
        return signatureRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IdResponse

        if (initiatorIdentity != other.initiatorIdentity) return false
        if (!Arrays.equals(initiatorNonce, other.initiatorNonce)) return false
        if (!Arrays.equals(remoteNonce, other.remoteNonce)) return false
        if (replyIdentity != other.replyIdentity) return false
        if (!Arrays.equals(signature, other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = initiatorIdentity.hashCode()
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        result = 31 * result + Arrays.hashCode(remoteNonce)
        result = 31 * result + replyIdentity.hashCode()
        result = 31 * result + Arrays.hashCode(signature)
        return result
    }
}