package uk.co.nesbit.crypto

import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.HashChainPublic.Companion.CHAIN_HASH_ID
import uk.co.nesbit.crypto.HashChainPublic.Companion.MAX_CHAIN_LENGTH
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class SecureVersion(val version: Int, val chainHash: SecureHash) : AvroConvertible {
    constructor(versionRecord: GenericRecord) :
            this(versionRecord.getTyped("version"),
                    versionRecord.getTyped("chainHash", ::SecureHash))

    companion object {
        val secureVersionSchema: Schema = Schema.Parser().addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema)).parse(SecureVersion::class.java.getResourceAsStream("/uk/co/nesbit/crypto/secureversion.avsc"))

        fun deserialize(bytes: ByteArray): SecureVersion {
            val secureVersionRecord = secureVersionSchema.deserialize(bytes)
            return SecureVersion(secureVersionRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val secureVersionRecord = GenericData.Record(secureVersionSchema)
        secureVersionRecord.putTyped("version", version)
        secureVersionRecord.putTyped("chainHash", chainHash)
        return secureVersionRecord
    }
}

class HashChainPublic(private val chainKey: SecretKeySpec, val targetHash: SecureHash) : AvroConvertible {
    constructor(keyMaterial: ByteArray, targetHash: SecureHash) : this(SecretKeySpec(keyMaterial, CHAIN_HASH_ID), targetHash)
    constructor(chainRecord: GenericRecord) :
            this(chainRecord.getTyped<ByteArray>("chainKey"),
                    chainRecord.getTyped("targetHash", ::SecureHash))

    companion object {
        val CHAIN_HASH_ID = "HmacSHA256"
        val MAX_CHAIN_LENGTH = 65536
        val hashChainSchema: Schema = Schema.Parser().
                addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema)).
                parse(HashChainPublic::class.java.getResourceAsStream("/uk/co/nesbit/crypto/hashchain.avsc"))

        fun deserialize(bytes: ByteArray): HashChainPublic {
            val hashChainRecord = hashChainSchema.deserialize(bytes)
            return HashChainPublic(hashChainRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val hashChainRecord = GenericData.Record(hashChainSchema)
        hashChainRecord.putTyped("chainKey", chainKey.encoded)
        hashChainRecord.putTyped("targetHash", targetHash)
        return hashChainRecord
    }

    fun verifyChainValue(version: SecureVersion): Boolean {
        require(version.chainHash.algorithm == CHAIN_HASH_ID)
        return verifyChainValue(version.chainHash.bytes, version.version)
    }

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int): Boolean {
        require(hash.algorithm == CHAIN_HASH_ID)
        return verifyChainValue(hash.bytes, stepsFromEnd)
    }

    fun verifyChainValue(hashBytes: ByteArray, stepsFromEnd: Int): Boolean {
        if (stepsFromEnd > MAX_CHAIN_LENGTH) {
            return false
        }
        val hmac = Mac.getInstance(CHAIN_HASH_ID)
        val endHash = hashBytes.copyOf()
        hmac.init(chainKey)
        for (i in 0 until stepsFromEnd) {
            hmac.update(endHash)
            hmac.doFinal(endHash, 0)
        }
        return org.bouncycastle.util.Arrays.constantTimeAreEqual(targetHash.bytes, endHash)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HashChainPublic

        if (chainKey != other.chainKey) return false
        if (targetHash != other.targetHash) return false

        return true
    }

    override fun hashCode(): Int {
        var result = chainKey.hashCode()
        result = 31 * result + targetHash.hashCode()
        return result
    }
}

class HashChainPrivate private constructor(private val chainKey: SecretKeySpec, val targetHash: SecureHash, private val seedHash: SecureHash, var version: Int) {
    companion object {
        fun generateChain(keyMaterial: ByteArray, secureRandom: SecureRandom = newSecureRandom()): HashChainPrivate {
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, CHAIN_HASH_ID)
            val endVal = getChainValueInternal(0, startHash, hmacKey)
            return HashChainPrivate(hmacKey, endVal, startHash, 0)
        }

        private fun getChainValueInternal(stepsFromEnd: Int, seed: SecureHash, hmacKey: SecretKeySpec): SecureHash {
            require(stepsFromEnd <= MAX_CHAIN_LENGTH)
            val hmac = Mac.getInstance(CHAIN_HASH_ID)
            val endHash = seed.bytes.copyOf()
            hmac.init(hmacKey)
            for (i in 0 until (MAX_CHAIN_LENGTH - stepsFromEnd)) {
                hmac.update(endHash)
                hmac.doFinal(endHash, 0)
            }
            return SecureHash(CHAIN_HASH_ID, endHash)
        }
    }

    fun getChainValue(stepsFromEnd: Int): SecureHash {
        require(stepsFromEnd <= MAX_CHAIN_LENGTH)
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        version = maxOf(stepsFromEnd, version)
        return getChainValueInternal(stepsFromEnd, seedHash, chainKey)
    }

    fun getSecureVersion(stepsFromEnd: Int): SecureVersion = SecureVersion(stepsFromEnd, getChainValue(stepsFromEnd))

    val public: HashChainPublic by lazy { HashChainPublic(chainKey, targetHash) }

}