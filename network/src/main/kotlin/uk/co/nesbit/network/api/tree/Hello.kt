package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.services.KeyService
import java.security.SignatureException

class Hello(
        val secureLinkId: ByteArray,
        val sourceId: VersionedIdentity,
        val signature: DigitalSignature
) : Message {
    constructor(helloRecord: GenericRecord) :
            this(
                    helloRecord.getTyped("secureLinkId"),
                    helloRecord.getTyped("sourceId"),
                    helloRecord.getTyped("signature")
            )

    init {
        require(secureLinkId.size == NONCE_SIZE) { "linkId must be 16 bytes in size" }
    }

    companion object {
        const val NONCE_SIZE = 16

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val helloSchema: Schema = Schema.Parser()
                .addTypes(
                        mapOf(
                                VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                                DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                        )
                )
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/hello.avsc"))

        val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", helloSchema)

        fun createHello(keyId: SecureHash, keyService: KeyService): Hello {
            val sourceId = keyService.getVersion(keyId)
            val linkId = ByteArray(NONCE_SIZE)
            keyService.random.nextBytes(linkId)
            val signingBytes = concatByteArrays(schemaFingerprint, linkId, sourceId.serialize())
            val signature = keyService.sign(keyId, signingBytes)
            return Hello(linkId, sourceId, signature.toDigitalSignature())
        }

        fun deserialize(bytes: ByteArray): Hello {
            val helloRecord = helloSchema.deserialize(bytes)
            return Hello(helloRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val helloRecord = GenericData.Record(helloSchema)
        helloRecord.putTyped("secureLinkId", secureLinkId)
        helloRecord.putTyped("sourceId", sourceId)
        helloRecord.putTyped("signature", signature)
        return helloRecord
    }

    fun verify(keyService: KeyService) {
        val bytesToVerify = concatByteArrays(schemaFingerprint, secureLinkId, sourceId.serialize())
        signature.verify(sourceId.identity.signingPublicKey, bytesToVerify)
        if (sourceId.currentVersion.minVersion < keyService.minVersion
            || sourceId.currentVersion.maxVersion > keyService.maxVersion
        ) {
            throw SignatureException("Peer versioned identity constraint weaker than local")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Hello

        if (!secureLinkId.contentEquals(other.secureLinkId)) return false
        if (sourceId != other.sourceId) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = secureLinkId.contentHashCode()
        result = 31 * result + sourceId.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }
}