package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import javax.crypto.spec.SecretKeySpec

data class SecureVersion(
    val version: Int,
    val chainHash: SecureHash,
    val maxVersion: Int,
    val minVersion: Int
) : AvroConvertible {
    constructor(versionRecord: GenericRecord) :
            this(
                versionRecord.getTyped("version"),
                versionRecord.getTyped("chainHash"),
                versionRecord.getTyped("maxVersion"),
                versionRecord.getTyped("minVersion")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val secureVersionSchema: Schema = Schema.Parser()
            .addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/secureversion.avsc"))

        fun deserialize(bytes: ByteArray): SecureVersion {
            val secureVersionRecord = secureVersionSchema.deserialize(bytes)
            return SecureVersion(secureVersionRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val secureVersionRecord = GenericData.Record(secureVersionSchema)
        secureVersionRecord.putTyped("version", version)
        secureVersionRecord.putTyped("chainHash", chainHash)
        secureVersionRecord.putTyped("maxVersion", maxVersion)
        secureVersionRecord.putTyped("minVersion", minVersion)
        return secureVersionRecord
    }
}

class HashChainPublic(
    private val chainKey: SecretKeySpec,
    val targetHash: SecureHash,
    val maxChainLength: Int,
    val minChainLength: Int
) : AvroConvertible {
    constructor(
        keyMaterial: ByteArray,
        targetHash: SecureHash,
        maxChainLength: Int,
        minChainLength: Int
    ) : this(
        SecretKeySpec(keyMaterial, CHAIN_HASH_ID),
        targetHash,
        maxChainLength,
        minChainLength
    )

    constructor(chainRecord: GenericRecord) :
            this(
                chainRecord.getTyped<ByteArray>("chainKey"),
                chainRecord.getTyped("targetHash"),
                chainRecord.getTyped("maxChainLength"),
                chainRecord.getTyped("minChainLength")
            )

    private val cache = mutableMapOf(targetHash to 0)

    init {
        require(minChainLength >= 0) { "min chain length cannot be negative" }
        require(minChainLength < maxChainLength) { "min chain length smaller than max chain length" }
    }

    companion object {
        const val CHAIN_HASH_ID = "HmacSHA256"
        const val MIN_CHAIN_LENGTH = 0
        const val MAX_CHAIN_LENGTH = 65536

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val hashChainSchema: Schema = Schema.Parser()
            .addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/hashchain.avsc"))

        fun deserialize(bytes: ByteArray): HashChainPublic {
            val hashChainRecord = hashChainSchema.deserialize(bytes)
            return HashChainPublic(hashChainRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val hashChainRecord = GenericData.Record(hashChainSchema)
        hashChainRecord.putTyped("chainKey", chainKey.encoded)
        hashChainRecord.putTyped("targetHash", targetHash)
        hashChainRecord.putTyped("maxChainLength", maxChainLength)
        hashChainRecord.putTyped("minChainLength", minChainLength)
        return hashChainRecord
    }

    fun verifyChainValue(version: SecureVersion): Boolean = verifyChainValue(
        version.chainHash,
        version.version,
        version.minVersion,
        version.maxVersion
    )

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int, minVersion: Int, maxVersion: Int): Boolean {
        require(hash.algorithm == CHAIN_HASH_ID)
        if (minVersion != minChainLength) {
            return false
        }
        if (maxVersion != maxChainLength) {
            return false
        }
        if (cache[hash] == stepsFromEnd) {
            return true
        }
        if (verifyChainValue(hash.bytes, stepsFromEnd, minVersion, maxVersion)) {
            cache[hash] = stepsFromEnd
            return true
        }
        return false
    }

    fun verifyChainValue(hashBytes: ByteArray, stepsFromEnd: Int, minVersion: Int, maxVersion: Int): Boolean {
        if (minVersion != minChainLength) {
            return false
        }
        if (maxVersion != maxChainLength) {
            return false
        }
        if (stepsFromEnd < minChainLength) {
            return false
        }
        if (stepsFromEnd > maxChainLength) {
            return false
        }
        val finalHash = ProviderCache.withMacInstance(CHAIN_HASH_ID) {
            val endHash = hashBytes.copyOf()
            init(chainKey)
            for (i in 0 until stepsFromEnd) {
                update(endHash)
                doFinal(endHash, 0)
            }
            endHash
        }
        return org.bouncycastle.util.Arrays.constantTimeAreEqual(targetHash.bytes, finalHash)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HashChainPublic

        if (chainKey != other.chainKey) return false
        if (targetHash != other.targetHash) return false
        if (minChainLength != other.minChainLength) return false
        if (maxChainLength != other.maxChainLength) return false

        return true
    }

    override fun hashCode(): Int {
        var result = chainKey.hashCode()
        result = 31 * result + targetHash.hashCode()
        result = 31 * result + minChainLength
        result = 31 * result + maxChainLength
        return result
    }

}

interface HashChainPrivate {
    val targetHash: SecureHash
    val version: Int
    val maxChainLength: Int
    val minChainLength: Int
    val secureVersion: SecureVersion
    val public: HashChainPublic
    fun getChainValue(stepsFromEnd: Int): SecureHash
    fun getSecureVersion(stepsFromEnd: Int): SecureVersion
}

