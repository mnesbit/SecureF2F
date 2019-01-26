package uk.co.nesbit.crypto

import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class SimpleHashChainPrivate private constructor(private val chainKey: SecretKeySpec,
                                                 override val targetHash: SecureHash,
                                                 private val seedHash: SecureHash,
                                                 override var version: Int,
                                                 override val maxChainLength: Int) : HashChainPrivate {
    companion object {
        fun generateChain(keyMaterial: ByteArray,
                          secureRandom: Random = newSecureRandom(),
                          maxChainLength: Int = HashChainPublic.MAX_CHAIN_LENGTH): HashChainPrivate {
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(HashChainPublic.CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, HashChainPublic.CHAIN_HASH_ID)
            val endVal = getChainValueInternal(0, startHash, hmacKey, maxChainLength)
            return SimpleHashChainPrivate(hmacKey, endVal, startHash, 0, maxChainLength)
        }

        private fun getChainValueInternal(stepsFromEnd: Int, seed: SecureHash, hmacKey: SecretKeySpec, maxChainLength: Int): SecureHash {
            require(stepsFromEnd <= maxChainLength)
            val hmac = Mac.getInstance(HashChainPublic.CHAIN_HASH_ID)
            val endHash = seed.bytes.copyOf()
            hmac.init(hmacKey)
            for (i in 0 until (maxChainLength - stepsFromEnd)) {
                hmac.update(endHash)
                hmac.doFinal(endHash, 0)
            }
            return SecureHash(HashChainPublic.CHAIN_HASH_ID, endHash)
        }
    }

    override fun getChainValue(stepsFromEnd: Int): SecureHash {
        require(stepsFromEnd <= maxChainLength)
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        version = maxOf(stepsFromEnd, version)
        return getChainValueInternal(stepsFromEnd, seedHash, chainKey, maxChainLength)
    }

    override fun getSecureVersion(stepsFromEnd: Int): SecureVersion = SecureVersion(stepsFromEnd, getChainValue(stepsFromEnd), maxChainLength)

    override val secureVersion: SecureVersion
        get() = getSecureVersion(version)

    override val public: HashChainPublic by lazy { HashChainPublic(chainKey, targetHash, maxChainLength) }

}