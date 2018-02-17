package uk.co.nesbit.crypto.session

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import java.security.PublicKey
import java.util.*

class SessionBinding(val otherPartyNonce: ByteArray,
                     val ownNonce: ByteArray,
                     val ownDHPublicKey: PublicKey,
                     val identityInfo: VersionedIdentity) : AvroConvertible {
    constructor(sessionBindingRecord: GenericRecord) :
            this(sessionBindingRecord.getTyped("otherPartyNonce"),
                    sessionBindingRecord.getTyped("ownNonce"),
                    sessionBindingRecord.getTyped("ownDHPublicKey"),
                    sessionBindingRecord.getTyped("identityInfo", ::VersionedIdentity))

    init {
        require(otherPartyNonce.size == NONCE_SIZE) { "invalid nonce" }
        require(ownNonce.size == NONCE_SIZE) { "invalid nonce" }
        require(ownDHPublicKey.algorithm == "Curve25519") { "invalid nonce" }
    }

    companion object {
        val sessionBindingSchema: Schema = Schema.Parser()
                .addTypes(mapOf(VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                        PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema))
                .parse(SessionBinding::class.java.getResourceAsStream("/uk/co/nesbit/crypto/session/sessionbinding.avsc"))

        fun deserialize(bytes: ByteArray): SessionBinding {
            val sessionBindingRecord = sessionBindingSchema.deserialize(bytes)
            return SessionBinding(sessionBindingRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val versionedIdentityRecord = GenericData.Record(sessionBindingSchema)
        versionedIdentityRecord.putTyped("otherPartyNonce", otherPartyNonce)
        versionedIdentityRecord.putTyped("ownNonce", ownNonce)
        versionedIdentityRecord.putTyped("ownDHPublicKey", ownDHPublicKey)
        versionedIdentityRecord.putTyped("identityInfo", identityInfo)
        return versionedIdentityRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SessionBinding

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(otherPartyNonce, other.otherPartyNonce)) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(ownNonce, other.ownNonce)) return false
        if (ownDHPublicKey != other.ownDHPublicKey) return false
        if (identityInfo != other.identityInfo) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Arrays.hashCode(otherPartyNonce)
        result = 31 * result + Arrays.hashCode(ownNonce)
        result = 31 * result + ownDHPublicKey.hashCode()
        result = 31 * result + identityInfo.hashCode()
        return result
    }
}