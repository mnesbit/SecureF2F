package uk.co.nesbit.crypto

import uk.co.nesbit.avro.serialize
import java.util.*

interface MerkleTreeHashDigestProvider {
    fun leafHash(index: Int, bytes: ByteArray): SecureHash
    fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash
}

private fun createNonce(random: Random): ByteArray {
    val nonce = ByteArray(16)
    random.nextBytes(nonce)
    return nonce
}

class DefaultHashDigestProvider : MerkleTreeHashDigestProvider {
    companion object {
        private val ONE_BYTE = ByteArray(1) { 1 }
    }

    override fun leafHash(index: Int, bytes: ByteArray): SecureHash {
        return SecureHash.doubleHash(concatByteArrays(ONE_BYTE, bytes))
    }

    override fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash {
        return SecureHash.doubleHash(concatByteArrays(depth.toByteArray(), left.bytes, right.bytes))
    }
}

class NonceHashDigestProvider(val entropy: ByteArray) : MerkleTreeHashDigestProvider {
    constructor(random: Random = newSecureRandom()) : this(createNonce(random))

    override fun leafHash(index: Int, bytes: ByteArray): SecureHash {
        val nonce = SecureHash.secureHash(concatByteArrays(index.toByteArray(), entropy))
        return SecureHash.secureHash(concatByteArrays(nonce.serialize(), bytes))
    }

    override fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash {
        return SecureHash.secureHash(
            SecureHash.doubleHash(concatByteArrays(depth.toByteArray(), left.bytes, right.bytes)).serialize()
        )
    }
}