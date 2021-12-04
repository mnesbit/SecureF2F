package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import java.util.*
import kotlin.math.ceil

class BloomFilter private constructor(
    private val bitCount: Int,
    private val hashRounds: Int,
    val hashSeed: Int,
    private val filterBits: BitSet
) : AvroConvertible {

    constructor(bloomFilterRecord: GenericRecord) :
            this(
                bloomFilterRecord.getTyped("bitCount"),
                bloomFilterRecord.getTyped("hashRounds"),
                bloomFilterRecord.getTyped("hashSeed"),
                BitSet.valueOf(bloomFilterRecord.getTyped<ByteArray>("filterBits"))
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val bloomFilterSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/bloomfilter.avsc"))

        fun deserialize(bytes: ByteArray): BloomFilter {
            val bloomFilterRecord = bloomFilterSchema.deserialize(bytes)
            return BloomFilter(bloomFilterRecord)
        }

        private val LN2: Double = Math.log(2.0)
        private val LN2_SQUARED: Double = LN2 * LN2

        private fun bitCountCalc(expectedItemCount: Int, falsePositiveRate: Double): Int {
            return ceil((-expectedItemCount.toDouble() * Math.log(falsePositiveRate)) / LN2_SQUARED).toInt()
        }

        fun createBloomFilter(
            expectedItemCount: Int,
            falsePositiveRate: Double,
            hashSeed: Int
        ): BloomFilter {
            val bitCount = bitCountCalc(expectedItemCount, falsePositiveRate)
            return BloomFilter(
                bitCount,
                ceil((bitCount * LN2) / expectedItemCount).toInt(),
                hashSeed,
                BitSet(bitCount)
            )
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val bloomFilterRecord = GenericData.Record(bloomFilterSchema)
        bloomFilterRecord.putTyped("bitCount", bitCount)
        bloomFilterRecord.putTyped("hashRounds", hashRounds)
        bloomFilterRecord.putTyped("hashSeed", hashSeed)
        bloomFilterRecord.putTyped("filterBits", filterBits.toByteArray())
        return bloomFilterRecord
    }

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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BloomFilter

        if (bitCount != other.bitCount) return false
        if (hashRounds != other.hashRounds) return false
        if (hashSeed != other.hashSeed) return false
        if (filterBits != other.filterBits) return false

        return true
    }

    override fun hashCode(): Int {
        var result = bitCount
        result = 31 * result + hashRounds
        result = 31 * result + hashSeed
        result = 31 * result + filterBits.hashCode()
        return result
    }

}