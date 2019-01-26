package uk.co.nesbit.crypto.session

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity

data class SessionIdentityProof(val identityInfo: VersionedIdentity,
                                val sessionBindingSignature: DigitalSignature,
                                val identityMAC: SecureHash) : AvroConvertible {
    constructor(sessionIdentityProofRecord: GenericRecord) :
            this(sessionIdentityProofRecord.getTyped("identityInfo", ::VersionedIdentity),
                    sessionIdentityProofRecord.getTyped("sessionBindingSignature", ::DigitalSignature),
                    sessionIdentityProofRecord.getTyped("identityMAC", ::SecureHash))

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val sessionIdentityProofSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/session/sessionidentityproof.avsc"))

        fun deserialize(bytes: ByteArray): SessionIdentityProof {
            val sessionIdentityProofRecord = sessionIdentityProofSchema.deserialize(bytes)
            return SessionIdentityProof(sessionIdentityProofRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val versionedIdentityRecord = GenericData.Record(sessionIdentityProofSchema)
        versionedIdentityRecord.putTyped("identityInfo", identityInfo)
        versionedIdentityRecord.putTyped("sessionBindingSignature", sessionBindingSignature)
        versionedIdentityRecord.putTyped("identityMAC", identityMAC)
        return versionedIdentityRecord
    }

}