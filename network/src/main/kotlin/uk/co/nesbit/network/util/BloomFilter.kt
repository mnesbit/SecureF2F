package uk.co.nesbit.network.util

import uk.co.nesbit.util.MurmurHash3
import java.util.*

class BloomFilter(val expectedItemCount: Int, val falsePositiveRate: Double, val hashSeed: Int) {
    companion object {
        private val LN2: Double = Math.log(2.0)
        private val LN2_SQUARED: Double = LN2 * LN2

        val EmptyFilter = BloomFilter(1, 0.02, 1)
    }

    val bitCount: Int = Math.ceil((-expectedItemCount.toDouble() * Math.log(falsePositiveRate)) / LN2_SQUARED).toInt()
    val hashRounds: Int = Math.ceil((bitCount * LN2) / expectedItemCount).toInt()

    private val filterBits = BitSet(bitCount)

    fun add(bytes: ByteArray) {
        val hash1 = Integer.toUnsignedLong(MurmurHash3.hash32(bytes, 0, bytes.size, hashSeed))
        val hash2 = Integer.toUnsignedLong(MurmurHash3.hash32(bytes, 0, bytes.size, hash1.toInt()))
        for (i in 0 until hashRounds) {
            val roundHash = (hash1 + i.toLong() * hash2)
            val hashPos = roundHash.rem(bitCount)
            filterBits.set(hashPos.toInt())
        }
    }

    fun possiblyContains(bytes: ByteArray): Boolean {
        val hash1 = Integer.toUnsignedLong(MurmurHash3.hash32(bytes, 0, bytes.size, hashSeed))
        val hash2 = Integer.toUnsignedLong(MurmurHash3.hash32(bytes, 0, bytes.size, hash1.toInt()))
        for (i in 0 until hashRounds) {
            val roundHash = (hash1 + i.toLong() * hash2)
            val hashPos = roundHash.rem(bitCount)
            if (!filterBits.get(hashPos.toInt())) {
                return false
            }
        }
        return true
    }
}