package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class SecureVersion(val version: Int, val chainHash: SecureHash) : AvroConvertible {
    constructor(versionRecord: GenericRecord) :
            this(versionRecord.getTyped("version"),
                    versionRecord.getTyped("chainHash", ::SecureHash))

    companion object {
        val secureVersionSchema: Schema = Schema.Parser()
                .addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
                .parse(SecureVersion::class.java.getResourceAsStream("/uk/co/nesbit/crypto/secureversion.avsc"))

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

    private val cache = mutableMapOf(targetHash to 0)

    companion object {
        const val CHAIN_HASH_ID = "HmacSHA256"
        const val MAX_CHAIN_LENGTH = 65536
        val hashChainSchema: Schema = Schema.Parser()
                .addTypes(mapOf(SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
                .parse(HashChainPublic::class.java.getResourceAsStream("/uk/co/nesbit/crypto/hashchain.avsc"))

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

    fun verifyChainValue(version: SecureVersion): Boolean = verifyChainValue(version.chainHash, version.version)

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int): Boolean {
        require(hash.algorithm == CHAIN_HASH_ID)
        if (cache[hash] == stepsFromEnd) {
            return true
        }
        if (verifyChainValue(hash.bytes, stepsFromEnd)) {
            cache[hash] = stepsFromEnd
            return true
        }
        return false
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

interface HashChainPrivate {
    val targetHash: SecureHash
    val version: Int
    val secureVersion: SecureVersion
    val public: HashChainPublic
    fun getChainValue(stepsFromEnd: Int): SecureHash
    fun getSecureVersion(stepsFromEnd: Int): SecureVersion
}

