package uk.co.nesbit.crypto.setsync

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.MurmurHash3
import uk.co.nesbit.crypto.newSecureRandom
import java.lang.Math.abs
import java.lang.Math.max
import java.util.*


// Based upon https://www.ics.uci.edu/~eppstein/pubs/EppGooUye-SIGCOMM-11.pdf
class SizeEstimator private constructor(
    val totalItems: Int,
    val baseSeed: Int,
    val strataEstimators: List<InvertibleBloomFilter>,
    val minHashEstimators: List<Int>
) : AvroConvertible {
    constructor(sizeEstimatorRecord: GenericRecord) : this(
        sizeEstimatorRecord.getTyped("totalItems"),
        sizeEstimatorRecord.getTyped("baseSeed"),
        sizeEstimatorRecord.getObjectArray("strataEstimators", ::InvertibleBloomFilter),
        sizeEstimatorRecord.getIntArray("minHashEstimators")
    )

    companion object {
        private const val MERSENNE_PRIME = 2147483647

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val sizeEstimatorSchema: Schema = Schema.Parser()
            .addTypes(mapOf(InvertibleBloomFilter.ibfSchema.fullName to InvertibleBloomFilter.ibfSchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("sizeestimator.avsc"))

        fun deserialize(bytes: ByteArray): SizeEstimator {
            val sizeEstimatorRecord = sizeEstimatorSchema.deserialize(bytes)
            return SizeEstimator(sizeEstimatorRecord)
        }

        fun createSizeEstimatorRequest(items: Set<Int>, random: Random = newSecureRandom()): SizeEstimator {
            val baseSeed = random.nextInt()
            val (strataEstimators, minHashEstimators) = calcForSeed(baseSeed, items)
            return SizeEstimator(
                items.size,
                baseSeed,
                strataEstimators,
                minHashEstimators
            )
        }

        private fun calcForSeed(
            baseSeed: Int,
            items: Set<Int>
        ): Pair<List<InvertibleBloomFilter>, MutableList<Int>> {
            val strataEstimators = List(7) { index -> InvertibleBloomFilter(baseSeed + index, 80) }
            val minHashEstimators = MutableList(2000) { Int.MAX_VALUE }
            val perms = minHashEstimators.indices.map { abs(MurmurHash3.hash32(it + baseSeed)) }
            for (item in items) {
                val itemHash = MurmurHash3.hash32(item)
                val leadingZeros = itemHash.countLeadingZeroBits()
                if (leadingZeros < strataEstimators.size) {
                    strataEstimators[leadingZeros].add(item)
                } else {
                    for (i in minHashEstimators.indices) {
                        val value = (i + itemHash * perms[i]).rem(MERSENNE_PRIME)
                        if (value < minHashEstimators[i]) {
                            minHashEstimators[i] = value
                        }
                    }
                }
            }
            return Pair(strataEstimators, minHashEstimators)
        }
    }

    fun calculateResponse(localItems: Set<Int>): InvertibleBloomFilter {
        val (localStrataEstimators, localMinHashEstimators) = calcForSeed(baseSeed, localItems)
        var count = 0
        for (i in (strataEstimators.size - 1) downTo -1) {
            if (i == -1) {
                break
            }
            val decode = localStrataEstimators[i].diff(strataEstimators[i]).decode()
            if (!decode.ok) {
                count *= (1 shl (i + 1))
                break
            }
            count += decode.added.size + decode.deleted.size
        }
        count = (1.5 * count).toInt()
        var minHashCount = 0
        for (i in minHashEstimators.indices) {
            if (minHashEstimators[i] == localMinHashEstimators[i]) ++minHashCount
        }
        val r = minHashCount.toDouble() / minHashEstimators.size.toDouble()
        val minhashd = (((1.0 - r) / (1.0 + r)) * (localItems.size + totalItems)).toInt()
        val sizediff = abs(localItems.size - totalItems)
        val estimate = 2 * max(max(sizediff, count), minhashd)
        return InvertibleBloomFilter.createIBF(baseSeed + 1, estimate, localItems)
    }

    override fun toGenericRecord(): GenericRecord {
        val sizeEstimatorRecord = GenericData.Record(sizeEstimatorSchema)
        sizeEstimatorRecord.putTyped("totalItems", totalItems)
        sizeEstimatorRecord.putTyped("baseSeed", baseSeed)
        sizeEstimatorRecord.putObjectArray("strataEstimators", strataEstimators)
        sizeEstimatorRecord.putIntArray("minHashEstimators", minHashEstimators)
        return sizeEstimatorRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SizeEstimator

        if (totalItems != other.totalItems) return false
        if (baseSeed != other.baseSeed) return false
        if (strataEstimators != other.strataEstimators) return false
        if (minHashEstimators != other.minHashEstimators) return false

        return true
    }

    override fun hashCode(): Int {
        var result = totalItems
        result = 31 * result + baseSeed
        result = 31 * result + strataEstimators.hashCode()
        result = 31 * result + minHashEstimators.hashCode()
        return result
    }
}