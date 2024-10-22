package uk.co.nesbit.crypto.session

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.generateNACLDHKeyPair
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.PROTO_VERSION
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*

// First packet in IKEv2 type handshake as described in: 'SIGMA: the `SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and its Use in the IKE Protocols'
// See http://webee.technion.ac.il/~hugo/sigma-pdf.pdf 'Full Fledge' Protocol
class InitiatorSessionParams private constructor(private val schemaId: SecureHash,
                                                 val protocolVersion: Int,
                                                 val initiatorNonce: ByteArray,
                                                 val initiatorDHPublicKey: PublicKey) : AvroConvertible {
    constructor(initiatorSessionParams: GenericRecord) :
            this(SecureHash("SHA-256", initiatorSessionParams.getTyped("schemaFingerprint")),
                    initiatorSessionParams.getTyped("protocolVersion"),
                    initiatorSessionParams.getTyped("initiatorNonce"),
                    initiatorSessionParams.getTyped("initiatorDHPublicKey"))

    init {
        require(protocolVersion == PROTO_VERSION) { "Incorrect protocol version $protocolVersion should be $PROTO_VERSION" }
        require(initiatorNonce.size == NONCE_SIZE) { "Invalid nonce" }
        require(schemaId == SecureHash("SHA-256", schemaFingerprint)) { "Schema mismatch" }
        require(initiatorDHPublicKey.algorithm == "NACLCurve25519") { "Only NACLCurve25519 Diffie-Hellman supported" }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val initiatorSessionParamsSchema: Schema = Schema.Parser()
                .addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema))
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/session/initiatorsessionparams.avsc"))
        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", initiatorSessionParamsSchema)

        fun deserialize(bytes: ByteArray): InitiatorSessionParams {
            val initiatorSessionParamsRecord = initiatorSessionParamsSchema.deserialize(bytes)
            return InitiatorSessionParams(initiatorSessionParamsRecord)
        }

        fun createInitiatorSession(random: SecureRandom = newSecureRandom()): Pair<KeyPair, InitiatorSessionParams> {
            val nonce = ByteArray(NONCE_SIZE)
            random.nextBytes(nonce)
            val ephemeralDHKeyPair = generateNACLDHKeyPair(random)
            return Pair(ephemeralDHKeyPair, InitiatorSessionParams(SecureHash("SHA-256", schemaFingerprint), PROTO_VERSION, nonce, ephemeralDHKeyPair.public))
        }
    }

    fun verify() {
        require(protocolVersion == PROTO_VERSION) { "Incorrect protocol version $protocolVersion should be $PROTO_VERSION" }
        require(initiatorNonce.size == NONCE_SIZE)
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(initiatorDHPublicKey.algorithm == "NACLCurve25519")
    }

    override fun toGenericRecord(): GenericRecord {
        val initiatorRecord = GenericData.Record(initiatorSessionParamsSchema)
        initiatorRecord.putTyped("schemaFingerprint", schemaFingerprint)
        initiatorRecord.putTyped("protocolVersion", protocolVersion)
        initiatorRecord.putTyped("initiatorNonce", initiatorNonce)
        initiatorRecord.putTyped("initiatorDHPublicKey", initiatorDHPublicKey)
        return initiatorRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InitiatorSessionParams

        if (schemaId != other.schemaId) return false
        if (protocolVersion != other.protocolVersion) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorNonce, other.initiatorNonce)) return false
        if (initiatorDHPublicKey != other.initiatorDHPublicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + protocolVersion.hashCode()
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        result = 31 * result + initiatorDHPublicKey.hashCode()
        return result
    }
}