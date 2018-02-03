package com.nesbit.crypto.session

import com.nesbit.avro.AvroConvertible
import com.nesbit.avro.deserialize
import com.nesbit.avro.getTyped
import com.nesbit.avro.putTyped
import com.nesbit.crypto.DigitalSignature
import com.nesbit.crypto.SecureHash
import com.nesbit.crypto.sphinx.VersionedIdentity
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord

data class SessionIdentityProof(val identityInfo: VersionedIdentity,
                                val sessionBindingSignature: DigitalSignature,
                                val identityMAC: SecureHash) : AvroConvertible {
    constructor(sessionIdentityProofRecord: GenericRecord) :
            this(sessionIdentityProofRecord.getTyped("identityInfo", ::VersionedIdentity),
                    sessionIdentityProofRecord.getTyped("sessionBindingSignature", ::DigitalSignature),
                    sessionIdentityProofRecord.getTyped("identityMAC", ::SecureHash))

    companion object {
        val sessionIdentityProofSchema: Schema = Schema.Parser().addTypes(mapOf(VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema)).parse(SessionIdentityProof::class.java.getResourceAsStream("/com/nesbit/crypto/session/sessionidentityproof.avsc"))

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