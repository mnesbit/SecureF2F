package uk.co.nesbit.crypto.merkle

import uk.co.nesbit.avro.serialize
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

class DefaultHashDigestProvider : MerkleTreeHashDigestProvider {
    companion object {
        private val ZERO_BYTE = ByteArray(1) { 1 }
        private val ONE_BYTE = ByteArray(1) { 1 }
    }

    override fun leafNonce(index: Int): ByteArray? = null

    override fun leafHash(index: Int, nonce: ByteArray?, bytes: ByteArray): SecureHash {
        require(nonce == null) { "Nonce must be null" }
        return SecureHash.doubleHash(concatByteArrays(ONE_BYTE, bytes))
    }

    override fun nodeHash(depth: Int, left: SecureHash, right: SecureHash): SecureHash {
        return SecureHash.doubleHash(concatByteArrays(ZERO_BYTE, left.bytes, right.bytes))
    }
}

class NonceHashDigestProvider(val entropy: ByteArray) : MerkleTreeHashDigestProvider {
    constructor(random: Random = newSecureRandom()) : this(createNonce(random))

    companion object {
        val DECODER_INSTANCE = NonceHashDigestProvider(ByteArray(0)) // no nonces created
    }

    override fun leafNonce(index: Int): ByteArray {
        require(entropy.isNotEmpty()) { "No entropy! Decoder instance being used by mistake?" }
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
}