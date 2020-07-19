package uk.co.nesbit.crypto

import uk.co.nesbit.crypto.HashChainPublic.Companion.CHAIN_HASH_ID
import java.util.*
import javax.crypto.spec.SecretKeySpec

// Based upon the pebbling algorithm in http://www.win.tue.nl/~berry/papers/eobp.pdf
// and code at http://www.win.tue.nl/~berry/pebbling/
class PebbledHashChain private constructor(
        private val chainKey: SecretKeySpec,
        override val targetHash: SecureHash,
        private val seedHash: SecureHash,
        private val intermediateHashes: MutableList<SecureHash>,
        override var version: Int,
        override val maxChainLength: Int,
        override val minChainLength: Int
) : HashChainPrivate {
    init {
        require(minChainLength >= 0) { "min chain length cannot be negative" }
        require(minChainLength < maxChainLength) { "min chain length smaller than max chain length" }
        require(version <= maxChainLength) { "version above allowed maxChainLength" }
    }

    companion object {
        fun generateChain(
                keyMaterial: ByteArray,
                secureRandom: Random = newSecureRandom(),
                maxChainLength: Int = HashChainPublic.MAX_CHAIN_LENGTH,
                minChainLength: Int = HashChainPublic.MIN_CHAIN_LENGTH
        ): HashChainPrivate {
            require(maxChainLength and (maxChainLength - 1) == 0) {
                "Maximum chain length must be a power of 2"
            }
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, CHAIN_HASH_ID)
            val intermediateHashes = mutableListOf<SecureHash>()
            val finalHash = ProviderCache.withMacInstance(CHAIN_HASH_ID) {
                val endHash = seed.copyOf()
                init(hmacKey)
                for (i in maxChainLength - 1 downTo 0) {
                    update(endHash)
                    doFinal(endHash, 0)
                    val j = i + 2
                    if ((j and (j - 1)) == 0) {
                        intermediateHashes.add(SecureHash(CHAIN_HASH_ID, endHash.copyOf()))
                    }
                }
                endHash
            }
            intermediateHashes.reverse()
            val chain = PebbledHashChain(
                    hmacKey,
                    SecureHash(CHAIN_HASH_ID, finalHash),
                    startHash,
                    intermediateHashes,
                    0,
                    maxChainLength,
                    minChainLength
            )
            for (i in 0 until minChainLength) {
                chain.incrementVersion()
            }
            return chain
        }
    }

    private data class Pebble(var q: Int, var g: Int)

    private val pebbles = mutableListOf<Pebble>()

    override val public: HashChainPublic by lazy(LazyThreadSafetyMode.PUBLICATION) {
        HashChainPublic(
                chainKey,
                targetHash,
                maxChainLength,
                minChainLength
        )
    }

    override fun getChainValue(stepsFromEnd: Int): SecureHash = getSecureVersion(stepsFromEnd).chainHash

    override val secureVersion: SecureVersion
        get() {
            if (version == maxChainLength - 1) {
                return SecureVersion(version, chain(seedHash), maxChainLength, minChainLength)
            }
            if (version == maxChainLength) {
                return SecureVersion(version, seedHash, maxChainLength, minChainLength)
            }
            return SecureVersion(version, intermediateHashes[0], maxChainLength, minChainLength)
        }

    override fun getSecureVersion(stepsFromEnd: Int): SecureVersion {
        require(stepsFromEnd >= minChainLength) { "Version $stepsFromEnd smaller than min version $minChainLength" }
        require(stepsFromEnd <= maxChainLength) { "Version $stepsFromEnd greater than max version $maxChainLength" }
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        while (version < stepsFromEnd) {
            incrementVersion()
        }
        return secureVersion
    }

    private fun chain(hash: SecureHash): SecureHash {
        return ProviderCache.withMacInstance(CHAIN_HASH_ID) {
            init(chainKey)
            update(hash.bytes)
            SecureHash(CHAIN_HASH_ID, doFinal())
        }
    }

    private fun incrementVersion() {
        if (version == maxChainLength) {
            return
        }
        ++version
        if (version == maxChainLength) {
            return
        }
        val r = maxChainLength - version
        var c = r
        var i = 0
        while ((c and 1) == 0) {
            intermediateHashes[i] = intermediateHashes[i + 1]
            i++
            c = c shr 1
        }
        ++i
        c = c shr 1
        if ((c and 1) == 1) {
            pebbles += Pebble(i, 0)
        }
        var u = pebbles.size
        var w = (r and 1) + i + 1
        while (c != 0) {
            while ((c and 1) == 0) {
                ++w
                c = c shr 1
            }
            --u
            val pebble = pebbles[u]
            for (d in 0 until (w shr 1)) {
                val hash = intermediateHashes[pebble.q]
                if (pebble.g == 0) {
                    --pebble.q
                    pebble.g = 1 shl pebble.q
                }
                intermediateHashes[pebble.q] = chain(hash)
                --pebble.g
            }
            if (pebble.q == 0) {
                pebbles.removeAt(pebbles.size - 1)
            }
            w = w and 1
            while ((c and 1) == 1) {
                ++w
                c = c shr 1
            }
        }
    }
}
