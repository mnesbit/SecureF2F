package uk.co.nesbit.crypto

import uk.co.nesbit.crypto.HashChainPublic.Companion.CHAIN_HASH_ID
import uk.co.nesbit.crypto.HashChainPublic.Companion.MAX_CHAIN_LENGTH
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

// Based upon the pebbling algorithm in http://www.win.tue.nl/~berry/papers/eobp.pdf
// and code at http://www.win.tue.nl/~berry/pebbling/
class PebbledHashChain private constructor(private val chainKey: SecretKeySpec,
                                           override val targetHash: SecureHash,
                                           private val seedHash: SecureHash,
                                           private val intermediateHashes: MutableList<SecureHash>,
                                           override var version: Int) : HashChainPrivate {
    companion object {
        fun generateChain(keyMaterial: ByteArray, secureRandom: Random = newSecureRandom()): HashChainPrivate {
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, CHAIN_HASH_ID)
            val hmac = Mac.getInstance(CHAIN_HASH_ID)
            val endHash = seed.copyOf()
            hmac.init(hmacKey)
            val intermediateHashes = mutableListOf<SecureHash>()
            for (i in MAX_CHAIN_LENGTH - 1 downTo 0) {
                hmac.update(endHash)
                hmac.doFinal(endHash, 0)
                val j = i + 2
                if ((j and (j - 1)) == 0) {
                    intermediateHashes.add(SecureHash(CHAIN_HASH_ID, endHash.copyOf()))
                }
            }
            intermediateHashes.reverse()
            return PebbledHashChain(hmacKey, SecureHash(CHAIN_HASH_ID, endHash), startHash, intermediateHashes, 0)
        }
    }

    private data class Pebble(var q: Int, var g: Int)

    private val pebbles = mutableListOf<Pebble>()

    override val public: HashChainPublic by lazy { HashChainPublic(chainKey, targetHash) }

    override fun getChainValue(stepsFromEnd: Int): SecureHash = getSecureVersion(stepsFromEnd).chainHash

    override val secureVersion: SecureVersion
        get() {
            if (version == MAX_CHAIN_LENGTH - 1) {
                return SecureVersion(version, chain(seedHash))
            }
            if (version == MAX_CHAIN_LENGTH) {
                return SecureVersion(version, seedHash)
            }
            return SecureVersion(version, intermediateHashes[0])
        }

    override fun getSecureVersion(stepsFromEnd: Int): SecureVersion {
        require(stepsFromEnd <= MAX_CHAIN_LENGTH)
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        while (version < stepsFromEnd) {
            incrementVersion()
        }
        return secureVersion
    }

    private fun chain(hash: SecureHash): SecureHash {
        val hmac = Mac.getInstance(CHAIN_HASH_ID)
        hmac.init(chainKey)
        hmac.update(hash.bytes)
        return SecureHash(CHAIN_HASH_ID, hmac.doFinal())
    }

    private fun incrementVersion() {
        if (version == MAX_CHAIN_LENGTH) {
            return
        }
        ++version
        if (version == MAX_CHAIN_LENGTH) {
            return
        }
        val r = MAX_CHAIN_LENGTH - version
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
