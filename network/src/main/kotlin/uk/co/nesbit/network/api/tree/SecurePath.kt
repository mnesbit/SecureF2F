package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.services.KeyService
import java.security.PublicKey
import java.security.SecureRandom
import java.time.Instant
import java.time.temporal.ChronoUnit

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

class EncryptedSecurePathItem private constructor(private val encryptedItem: ByteArray) : AvroConvertible {
    constructor(encryptedSecurePathItemRecord: GenericRecord) : this(
        encryptedSecurePathItemRecord.getTyped<ByteArray>("encryptedItem")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val encryptedSecurePathItemSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/encryptedsecurepathitem.avsc"))

        fun createEncryptedSecurePathItem(
            securePathItem: SecurePathItem,
            targetPublicKey: PublicKey,
            random: SecureRandom = newSecureRandom()
        ): EncryptedSecurePathItem {
            val payload = securePathItem.serialize()
            val encrypted = Ecies.encryptMessage(payload, null, targetPublicKey, random)
            return EncryptedSecurePathItem(encrypted)
        }

        fun deserialize(bytes: ByteArray): EncryptedSecurePathItem {
            val encryptedSecurePathItemRecord = encryptedSecurePathItemSchema.deserialize(bytes)
            return EncryptedSecurePathItem(encryptedSecurePathItemRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val encryptedSecurePathItemRecord = GenericData.Record(encryptedSecurePathItemSchema)
        encryptedSecurePathItemRecord.putTyped("encryptedItem", encryptedItem)
        return encryptedSecurePathItemRecord
    }

    fun decrypt(finalNodeId: SecureHash, keyService: KeyService): SecurePathItem {
        val finalAddress = keyService.getVersion(finalNodeId)
        val decrypted = Ecies.decryptMessage(encryptedItem, null, finalAddress.identity.diffieHellmanPublicKey) { x ->
            keyService.getSharedDHSecret(finalNodeId, x)
        }
        return SecurePathItem.deserialize(decrypted)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EncryptedSecurePathItem

        if (!encryptedItem.contentEquals(other.encryptedItem)) return false

        return true
    }

    override fun hashCode(): Int {
        return encryptedItem.contentHashCode()
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

        fun createSecurePathList(
            appendTo: List<SecurePathItem>?,
            from: VersionedIdentity,
            to: VersionedIdentity,
            keyService: KeyService,
            now: Instant
        ): List<SecurePathItem> {
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val nowBytes = truncatedNow.toEpochMilli().toByteArray()
            val pathSignOverNext = concatByteArrays(nowBytes, to.id.serialize())
            val signatureOverNext = keyService.sign(from.id, pathSignOverNext).toDigitalSignature()
            val prevPath = appendTo ?: emptyList()
            val pathList = prevPath + SecurePathItem(truncatedNow, from, signatureOverNext)
            return pathList
        }

        fun createEncryptedSecurePathList(
            appendTo: List<EncryptedSecurePathItem>?,
            from: VersionedIdentity,
            to: VersionedIdentity,
            finalDestination: SphinxPublicIdentity,
            keyService: KeyService,
            now: Instant
        ): List<EncryptedSecurePathItem> {
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val nowBytes = truncatedNow.toEpochMilli().toByteArray()
            val pathSignOverNext = concatByteArrays(nowBytes, to.id.serialize())
            val signatureOverNext = keyService.sign(from.id, pathSignOverNext).toDigitalSignature()
            val pathItem = SecurePathItem(truncatedNow, from, signatureOverNext)
            val encryptedPathItem = EncryptedSecurePathItem.createEncryptedSecurePathItem(
                pathItem,
                finalDestination.diffieHellmanPublicKey,
                keyService.random
            )
            val prevPath = appendTo ?: emptyList()
            return prevPath + encryptedPathItem
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
