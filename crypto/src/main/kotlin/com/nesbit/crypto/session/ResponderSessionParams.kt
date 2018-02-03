package com.nesbit.crypto.session

import com.nesbit.avro.AvroConvertible
import com.nesbit.avro.deserialize
import com.nesbit.avro.getTyped
import com.nesbit.avro.putTyped
import com.nesbit.crypto.PublicKeyHelper
import com.nesbit.crypto.SecureHash
import com.nesbit.crypto.generateCurve25519DHKeyPair
import com.nesbit.crypto.newSecureRandom
import com.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*

class ResponderSessionParams(val schemaId: SecureHash,
                             val initiatorNonce: ByteArray,
                             val responderNonce: ByteArray,
                             val responderDHPublicKey: PublicKey) : AvroConvertible {
    constructor(responderSessionParams: GenericRecord) :
            this(SecureHash("SHA-256", responderSessionParams.getTyped("schemaFingerprint")),
                    responderSessionParams.getTyped("initiatorNonce"),
                    responderSessionParams.getTyped("responderNonce"),
                    responderSessionParams.getTyped("responderDHPublicKey")) {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
    }

    init {
        require(initiatorNonce.size == NONCE_SIZE)
        require(responderNonce.size == NONCE_SIZE)
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(responderDHPublicKey.algorithm == "Curve25519")
    }

    companion object {
        val responderSessionParamsSchema: Schema = Schema.Parser().addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema)).parse(ResponderSessionParams::class.java.getResourceAsStream("/com/nesbit/crypto/session/responderSessionParams.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", responderSessionParamsSchema)

        fun deserialize(bytes: ByteArray): ResponderSessionParams {
            val responderSessionParamsRecord = responderSessionParamsSchema.deserialize(bytes)
            return ResponderSessionParams(responderSessionParamsRecord)
        }

        fun createResponderSession(initiatorParams: InitiatorSessionParams,
                                   random: SecureRandom = newSecureRandom()): Pair<KeyPair, ResponderSessionParams> {
            val nonce = ByteArray(NONCE_SIZE)
            random.nextBytes(nonce)
            val ephemeralDHKeyPair = generateCurve25519DHKeyPair(random)
            return Pair(ephemeralDHKeyPair, ResponderSessionParams(SecureHash("SHA-256", schemaFingerprint), initiatorParams.initiatorNonce, nonce, ephemeralDHKeyPair.public))
        }
    }

    init {
        require(responderNonce.size == NONCE_SIZE)
    }

    fun verify(initiatorParams: InitiatorSessionParams) {
        require(initiatorNonce.size == NONCE_SIZE)
        require(responderNonce.size == NONCE_SIZE)
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(responderDHPublicKey.algorithm == "Curve25519")
        require(org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorParams.initiatorNonce, initiatorNonce)) { "Inconsistent Nonce" }
        require(!org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorNonce, responderNonce)) { "Echoed nonce" }
        require(!org.bouncycastle.util.Arrays.constantTimeAreEqual(responderDHPublicKey.encoded,
                initiatorParams.initiatorDHPublicKey.encoded)) { "Echoed key" }
        initiatorParams.verify()
    }

    override fun toGenericRecord(): GenericRecord {
        val responderRecord = GenericData.Record(responderSessionParamsSchema)
        responderRecord.putTyped("schemaFingerprint", schemaFingerprint)
        responderRecord.putTyped("initiatorNonce", initiatorNonce)
        responderRecord.putTyped("responderNonce", responderNonce)
        responderRecord.putTyped("responderDHPublicKey", responderDHPublicKey)
        return responderRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ResponderSessionParams

        if (schemaId != other.schemaId) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorNonce, other.initiatorNonce)) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(responderNonce, other.responderNonce)) return false
        if (responderDHPublicKey != other.responderDHPublicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        result = 31 * result + Arrays.hashCode(responderNonce)
        result = 31 * result + responderDHPublicKey.hashCode()
        return result
    }
}