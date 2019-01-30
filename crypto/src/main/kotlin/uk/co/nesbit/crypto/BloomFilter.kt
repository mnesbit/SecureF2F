package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import java.util.*

class BloomFilter private constructor(
    val expectedItemCount: Int,
    val falsePositiveRate: Double,
    val hashSeed: Int,
    private val filterBits: BitSet
) : AvroConvertible {

    private val bitCount: Int = bitCountCalc(expectedItemCount, falsePositiveRate)
    private val hashRounds: Int = Math.ceil((bitCount * LN2) / expectedItemCount).toInt()

    constructor(bloomFilterRecord: GenericRecord) :
            this(
                bloomFilterRecord.getTyped("expectedItemCount"),
                bloomFilterRecord.getTyped("falsePositiveRate"),
                bloomFilterRecord.getTyped("hashSeed"),
                BitSet.valueOf(bloomFilterRecord.getTyped<ByteArray>("filterBits"))
            )

    constructor (
        expectedItemCount: Int,
        falsePositiveRate: Double,
        hashSeed: Int
    ) : this(
        expectedItemCount,
        falsePositiveRate,
        hashSeed,
        BitSet(bitCountCalc(expectedItemCount, falsePositiveRate))
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

        fun bitCountCalc(expectedItemCount: Int, falsePositiveRate: Double): Int {
            return Math.ceil((-expectedItemCount.toDouble() * Math.log(falsePositiveRate)) / LN2_SQUARED).toInt()
        }

        val EmptyFilter = BloomFilter(1, 0.02, 1)
    }

    override fun toGenericRecord(): GenericRecord {
        val bloomFilterRecord = GenericData.Record(bloomFilterSchema)
        bloomFilterRecord.putTyped("expectedItemCount", expectedItemCount)
        bloomFilterRecord.putTyped("falsePositiveRate", falsePositiveRate)
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

        if (expectedItemCount != other.expectedItemCount) return false
        if (falsePositiveRate != other.falsePositiveRate) return false
        if (hashSeed != other.hashSeed) return false
        if (filterBits != other.filterBits) return false

        return true
    }

    override fun hashCode(): Int {
        var result = expectedItemCount
        result = 31 * result + falsePositiveRate.hashCode()
        result = 31 * result + hashSeed
        result = 31 * result + filterBits.hashCode()
        return result
    }
}