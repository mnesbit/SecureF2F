package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import java.time.Instant

class SecurePathItem(
    val timestamp: Instant,
    val identity: VersionedIdentity,
    val signatureOverNext: DigitalSignature
) : AvroConvertible {
    constructor(securePathItemRecord: GenericRecord) : this(
        securePathItemRecord.getTyped("timestamp"),
        securePathItemRecord.getTyped("identity"),
        securePathItemRecord.getTyped("signatureOverNext")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val securePathItemSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/securepathitem.avsc"))

        fun deserialize(bytes: ByteArray): SecurePathItem {
            val securePathItemRecord = securePathItemSchema.deserialize(bytes)
            return SecurePathItem(securePathItemRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val securePathItemRecord = GenericData.Record(securePathItemSchema)
        securePathItemRecord.putTyped("timestamp", timestamp)
        securePathItemRecord.putTyped("identity", identity)
        securePathItemRecord.putTyped("signatureOverNext", signatureOverNext)
        return securePathItemRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SecurePathItem

        if (timestamp != other.timestamp) return false
        if (identity != other.identity) return false
        if (signatureOverNext != other.signatureOverNext) return false

        return true
    }

    override fun hashCode(): Int {
        var result = timestamp.hashCode()
        result = 31 * result + identity.hashCode()
        result = 31 * result + signatureOverNext.hashCode()
        return result
    }
}

class SecurePath(val path: List<SecurePathItem>) : AvroConvertible {
    constructor(securePathRecord: GenericRecord) : this(
        securePathRecord.getObjectArray("path", ::SecurePathItem)
    )

    init {
        require(path.isNotEmpty()) { "SecurePath cannot be empty" }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val securePathSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecurePathItem.securePathItemSchema.fullName to SecurePathItem.securePathItemSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/securepath.avsc"))

        fun deserialize(bytes: ByteArray): SecurePath {
            val securePathRecord = securePathSchema.deserialize(bytes)
            return SecurePath(securePathRecord)
        }
    }

    val shortPath: List<SphinxPublicIdentity> get() = path.map { it.identity.identity }

    override fun toGenericRecord(): GenericRecord {
        val securePathRecord = GenericData.Record(securePathSchema)
        securePathRecord.putObjectArray("path", path)
        return securePathRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SecurePath

        if (path != other.path) return false

        return true
    }

    override fun hashCode(): Int {
        return path.hashCode()
    }
}
