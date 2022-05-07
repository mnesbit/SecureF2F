package uk.co.nesbit.crypto.merkle

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.toByteArray
import java.util.*

interface MerkleTreeHashDigestProvider {
    fun leafNonce(index: Int): ByteArray?
    fun leafHash(index: Int, nonce: ByteArray?, bytes: ByteArray): SecureHash
    fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash
}

private fun createNonce(random: Random): ByteArray {
    val nonce = ByteArray(16)
    random.nextBytes(nonce)
    return nonce
}

// The classic tree algorithm (e.g. RFC6962) using 0x00 prefix for leaves and 0x01 for nodes
// and SHA2-256 double hashing throughout
// Nonce is just null for this style of provider
object DefaultHashDigestProvider : MerkleTreeHashDigestProvider {
    private val ZERO_BYTE = ByteArray(1) { 1 }
    private val ONE_BYTE = ByteArray(1) { 1 }

    override fun leafNonce(index: Int): ByteArray? = null

    override fun leafHash(index: Int, nonce: ByteArray?, bytes: ByteArray): SecureHash {
        require(nonce == null) { "Nonce must be null" }
        return SecureHash.doubleHash(concatByteArrays(ZERO_BYTE, bytes))
    }

    override fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash {
        return SecureHash.doubleHash(concatByteArrays(ONE_BYTE, left.bytes, right.bytes))
    }
}

// Simple variant of standard hashing, for use where Merkle trees are used in different roles and
// need to be different to protect against copy-paste attacks
class TweakableHashDigestProvider(
    val leafPrefix: ByteArray,
    val nodePrefix: ByteArray
) : MerkleTreeHashDigestProvider {
    init {
        require(!leafPrefix.contentEquals(nodePrefix)) {
            "Hash prefix for nodes must be different to that for leaves"
        }
    }

    override fun leafNonce(index: Int): ByteArray? = null

    override fun leafHash(index: Int, nonce: ByteArray?, bytes: ByteArray): SecureHash {
        require(nonce == null) { "Nonce must be null" }
        return SecureHash.doubleHash(concatByteArrays(leafPrefix, bytes))
    }

    override fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash {
        return SecureHash.doubleHash(concatByteArrays(nodePrefix, left.bytes, right.bytes))
    }
}

// This doesn't support log audit proofs as it uses depth in the node hashes
// However, it is suited to low entropy leaves, such as blockchain transactions
class NonceHashDigestProvider(val entropy: ByteArray) : MerkleTreeHashDigestProvider, AvroConvertible {
    constructor(random: Random = newSecureRandom()) : this(createNonce(random))
    constructor(nonceDigestRecord: GenericRecord) : this(
        nonceDigestRecord.getTyped<ByteArray>("entropy")
    )

    companion object {
        // use this instance if only verification is required and thus don't need to reveal the entropy
        val VERIFY_INSTANCE = NonceHashDigestProvider(ByteArray(0))

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val nonceHashDigestProviderSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("noncehashdigestprovider.avsc"))

        fun deserialize(bytes: ByteArray): NonceHashDigestProvider {
            val nonceDigestRecord = nonceHashDigestProviderSchema.deserialize(bytes)
            return NonceHashDigestProvider(nonceDigestRecord)
        }
    }

    override fun leafNonce(index: Int): ByteArray {
        require(entropy.isNotEmpty()) { "No entropy! VERIFY_INSTANCE being used to create proof by mistake?" }
        return SecureHash.secureHash(concatByteArrays(index.toByteArray(), entropy)).serialize()
    }

    override fun leafHash(index: Int, nonce: ByteArray?, bytes: ByteArray): SecureHash {
        require(nonce != null) { "Nonce must not be null" }
        return SecureHash.secureHash(concatByteArrays(nonce, bytes))
    }

    override fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash {
        return SecureHash.secureHash(
            SecureHash.doubleHash(concatByteArrays(depth.toByteArray(), left.bytes, right.bytes)).serialize()
        )
    }

    override fun toGenericRecord(): GenericRecord {
        val nonceDigestRecord = GenericData.Record(nonceHashDigestProviderSchema)
        nonceDigestRecord.putTyped("entropy", entropy)
        return nonceDigestRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NonceHashDigestProvider

        if (!entropy.contentEquals(other.entropy)) return false

        return true
    }

    override fun hashCode(): Int {
        return entropy.contentHashCode()
    }
}