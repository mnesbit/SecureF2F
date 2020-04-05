package uk.co.nesbit.crypto

import java.util.*
import javax.crypto.spec.SecretKeySpec

class SimpleHashChainPrivate private constructor(
    private val chainKey: SecretKeySpec,
    override val targetHash: SecureHash,
    private val seedHash: SecureHash,
    override var version: Int,
    override val maxChainLength: Int,
    override val minChainLength: Int
) : HashChainPrivate {
    init {
        require(minChainLength >= 0) { "min chain length cannot be negative" }
        require(minChainLength < maxChainLength) { "min chain length smaller than max chain length" }
        require(version >= minChainLength) { "version below allowed minChainLength" }
        require(version <= maxChainLength) { "version above allowed maxChainLength" }
    }

    companion object {
        fun generateChain(
            keyMaterial: ByteArray,
            secureRandom: Random = newSecureRandom(),
            maxChainLength: Int = HashChainPublic.MAX_CHAIN_LENGTH,
            minChainLength: Int = HashChainPublic.MIN_CHAIN_LENGTH
        ): HashChainPrivate {
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(HashChainPublic.CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, HashChainPublic.CHAIN_HASH_ID)
            val endVal = getChainValueInternal(
                0,
                startHash,
                hmacKey,
                maxChainLength,
                0
            )
            return SimpleHashChainPrivate(
                hmacKey,
                endVal,
                startHash,
                minChainLength,
                maxChainLength,
                minChainLength
            )
        }

        private fun getChainValueInternal(
            stepsFromEnd: Int,
            seed: SecureHash,
            hmacKey: SecretKeySpec,
            maxChainLength: Int,
            minChainLength: Int
        ): SecureHash {
            require(stepsFromEnd >= minChainLength)
            require(stepsFromEnd <= maxChainLength)
            return ProviderCache.withMacInstance(HashChainPublic.CHAIN_HASH_ID) {
                val endHash = seed.bytes.copyOf()
                init(hmacKey)
                for (i in 0 until (maxChainLength - stepsFromEnd)) {
                    update(endHash)
                    doFinal(endHash, 0)
                }
                SecureHash(HashChainPublic.CHAIN_HASH_ID, endHash)
            }
        }
    }

    override fun getChainValue(stepsFromEnd: Int): SecureHash {
        require(stepsFromEnd >= minChainLength)
        require(stepsFromEnd <= maxChainLength)
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        version = maxOf(stepsFromEnd, version)
        return getChainValueInternal(stepsFromEnd, seedHash, chainKey, maxChainLength, minChainLength)
    }

    override fun getSecureVersion(stepsFromEnd: Int): SecureVersion = SecureVersion(
        stepsFromEnd,
        getChainValue(stepsFromEnd),
        maxChainLength,
        minChainLength
    )

    override val secureVersion: SecureVersion
        get() = getSecureVersion(version)

    override val public: HashChainPublic by lazy(LazyThreadSafetyMode.PUBLICATION) {
        HashChainPublic(
            chainKey,
            targetHash,
            maxChainLength,
            minChainLength
        )
    }

}