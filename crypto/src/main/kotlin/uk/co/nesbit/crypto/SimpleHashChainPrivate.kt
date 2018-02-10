package uk.co.nesbit.crypto

import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class SimpleHashChainPrivate private constructor(private val chainKey: SecretKeySpec, override val targetHash: SecureHash, private val seedHash: SecureHash, override var version: Int) : HashChainPrivate {
    companion object {
        fun generateChain(keyMaterial: ByteArray, secureRandom: Random = newSecureRandom()): HashChainPrivate {
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(HashChainPublic.CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, HashChainPublic.CHAIN_HASH_ID)
            val endVal = getChainValueInternal(0, startHash, hmacKey)
            return SimpleHashChainPrivate(hmacKey, endVal, startHash, 0)
        }

        private fun getChainValueInternal(stepsFromEnd: Int, seed: SecureHash, hmacKey: SecretKeySpec): SecureHash {
            require(stepsFromEnd <= HashChainPublic.MAX_CHAIN_LENGTH)
            val hmac = Mac.getInstance(HashChainPublic.CHAIN_HASH_ID)
            val endHash = seed.bytes.copyOf()
            hmac.init(hmacKey)
            for (i in 0 until (HashChainPublic.MAX_CHAIN_LENGTH - stepsFromEnd)) {
                hmac.update(endHash)
                hmac.doFinal(endHash, 0)
            }
            return SecureHash(HashChainPublic.CHAIN_HASH_ID, endHash)
        }
    }

    override fun getChainValue(stepsFromEnd: Int): SecureHash {
        require(stepsFromEnd <= HashChainPublic.MAX_CHAIN_LENGTH)
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        version = maxOf(stepsFromEnd, version)
        return getChainValueInternal(stepsFromEnd, seedHash, chainKey)
    }

    override fun getSecureVersion(stepsFromEnd: Int): SecureVersion = SecureVersion(stepsFromEnd, getChainValue(stepsFromEnd))

    override val secureVersion: SecureVersion
        get() = getSecureVersion(version)

    override val public: HashChainPublic by lazy { HashChainPublic(chainKey, targetHash) }

}