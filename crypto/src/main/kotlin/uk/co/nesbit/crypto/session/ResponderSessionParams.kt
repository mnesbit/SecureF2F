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
import uk.co.nesbit.crypto.generateCurve25519DHKeyPair
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.PROTO_VERSION
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*

// Second packet in IKEv2 type handshake as described in: 'SIGMA: the `SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and its Use in the IKE Protocols'
// See http://webee.technion.ac.il/~hugo/sigma-pdf.pdf 'Full Fledge' Protocol
class ResponderSessionParams private constructor(private val schemaId: SecureHash,
                                                 val protocolVersion: Int,
                                                 private val initiatorNonce: ByteArray,
                                                 val responderNonce: ByteArray,
                                                 val responderDHPublicKey: PublicKey) : AvroConvertible {
    constructor(responderSessionParams: GenericRecord) :
            this(SecureHash("SHA-256", responderSessionParams.getTyped("schemaFingerprint")),
                    responderSessionParams.getTyped("protocolVersion"),
                    responderSessionParams.getTyped("initiatorNonce"),
                    responderSessionParams.getTyped("responderNonce"),
                    responderSessionParams.getTyped("responderDHPublicKey")) {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
    }

    init {
        require(protocolVersion == PROTO_VERSION) { "Incorrect protocol version $protocolVersion should be $PROTO_VERSION" }
        require(initiatorNonce.size == NONCE_SIZE) { "Invalid nonce" }
        require(responderNonce.size == NONCE_SIZE) { "Invalid nonce" }
        require(schemaId == SecureHash("SHA-256", schemaFingerprint)) { "Schema mismatch" }
        require(responderDHPublicKey.algorithm == "Curve25519") { "Only Curve25519 Diffie-Hellman supported" }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val responderSessionParamsSchema: Schema = Schema.Parser()
            .addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/session/respondersessionparams.avsc"))

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
            return Pair(ephemeralDHKeyPair, ResponderSessionParams(SecureHash("SHA-256", schemaFingerprint), PROTO_VERSION, initiatorParams.initiatorNonce, nonce, ephemeralDHKeyPair.public))
        }
    }

    fun verify(initiatorParams: InitiatorSessionParams) {
        require(protocolVersion == PROTO_VERSION) { "Incorrect protocol version $protocolVersion should be $PROTO_VERSION" }
        require(initiatorParams.protocolVersion == protocolVersion) { "Incorrect protocol version ${initiatorParams.protocolVersion} should be $PROTO_VERSION" }
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
        responderRecord.putTyped("protocolVersion", protocolVersion)
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
        if (protocolVersion != other.protocolVersion) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(initiatorNonce, other.initiatorNonce)) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(responderNonce, other.responderNonce)) return false
        if (responderDHPublicKey != other.responderDHPublicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + protocolVersion.hashCode()
        result = 31 * result + Arrays.hashCode(initiatorNonce)
        result = 31 * result + Arrays.hashCode(responderNonce)
        result = 31 * result + responderDHPublicKey.hashCode()
        return result
    }
}