package uk.co.nesbit.crypto.setsync

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.MurmurHash3
import uk.co.nesbit.crypto.setsync.InvertibleBloomEntry.Companion.ibfEntrySchema
import java.lang.Math.abs
import java.lang.Math.max

// Based upon https://www.ics.uci.edu/~eppstein/pubs/EppGooUye-SIGCOMM-11.pdf
class InvertibleBloomFilter private constructor(
    val seed: Int,
    val entries: List<InvertibleBloomEntry>
) : AvroConvertible {
    constructor(ibfRecord: GenericRecord) : this(
        ibfRecord.getTyped("seed"),
        ibfRecord.getObjectArray("entries", ::InvertibleBloomEntry)
    )

    constructor(seed: Int, size: Int) : this(
        seed,
        List(max(size, 4)) { _ -> InvertibleBloomEntry() }
    )

    companion object {
        const val NUM_HASHES = 4

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val ibfSchema: Schema = Schema.Parser()
            .addTypes(mapOf(ibfEntrySchema.fullName to ibfEntrySchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("invertiblebloomfilter.avsc"))

        fun deserialize(bytes: ByteArray): InvertibleBloomFilter {
            val ibfRecord = ibfSchema.deserialize(bytes)
            return InvertibleBloomFilter(ibfRecord)
        }

        fun createIBF(seed: Int, size: Int, items: Set<Int>): InvertibleBloomFilter {
            val ibf = InvertibleBloomFilter(seed, size)
            for (item in items) {
                ibf.add(item)
            }
            return ibf
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val ibfRecord = GenericData.Record(ibfSchema)
        ibfRecord.putTyped("seed", seed)
        ibfRecord.putObjectArray("entries", entries)
        return ibfRecord
    }

    fun add(newKey: Int) {
        val hashes = selectBins(newKey)
        for (index in hashes) {
            entries[index].add(newKey)
        }
    }

    fun diff(other: InvertibleBloomFilter): InvertibleBloomFilter {
        require(seed == other.seed) { "mismatched seed" }
        require(entries.size == other.entries.size) { "mismatched filter size" }
        val newEntries = ArrayList<InvertibleBloomEntry>(entries.size)
        for (i in entries.indices) {
            newEntries.add(entries[i].diff(other.entries[i]))
        }
        return InvertibleBloomFilter(seed, newEntries)
    }

    data class DecodeResult(
        val added: Set<Int>, // present locally, missing in other
        val deleted: Set<Int>, // missing locally, present in other
        val ok: Boolean
    )

    fun decode(localItems: Set<Int>): DecodeResult {
        val matchedIBF = createIBF(seed, entries.size, localItems)
        val diff = matchedIBF.diff(this)
        val decode = diff.decode()
        return DecodeResult(
            decode.deleted,
            decode.added,
            decode.ok
        ) // swap perspective for consistency with manual diff then decode
    }

    fun decode(): DecodeResult {
        val pureIndexQueue = ArrayDeque<Int>()
        val added = mutableSetOf<Int>()
        val deleted = mutableSetOf<Int>()
        for (index in entries.indices) {
            if (entries[index].isPure) {
                pureIndexQueue.addFirst(index)
            }
        }
        while (pureIndexQueue.isNotEmpty()) {
            val nextIndex = pureIndexQueue.removeFirst()
            val pureEntry = entries[nextIndex]
            if (!pureEntry.isPure) {
                continue
            }
            val decodedKey = pureEntry.key
            val decodedCount = pureEntry.count
            if (decodedCount > 0) {
                added += decodedKey
            } else {
                deleted += decodedKey
            }
            val hashes = selectBins(decodedKey)
            for (index in hashes) {
                if (decodedCount > 0) {
                    entries[index].sub(decodedKey)
                } else {
                    entries[index].add(decodedKey)
                }
                if (entries[index].isPure) {
                    pureIndexQueue.addFirst(index)
                }
            }
        }
        if (entries.any { !it.isEmpty }) {
            return DecodeResult(emptySet(), emptySet(), false)
        }
        return DecodeResult(added, deleted, true)
    }

    private fun selectBins(newKey: Int): Set<Int> {
        val hashes = mutableSetOf<Int>()
        val hash1 = MurmurHash3.hash32(newKey.toLong() + 0x123456789ABCDEFL)
        val hash2 = MurmurHash3.hash32(newKey.toLong() + 65521L * seed.toLong())
        for (i in 1..NUM_HASHES) {
            val roundHash = abs(hash1 + i * hash2)
            if (roundHash >= 0) { // Int.MIN_VALUE comes out negative from abs!!
                hashes += roundHash.rem(entries.size)
            }
        }
        return hashes
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InvertibleBloomFilter

        if (seed != other.seed) return false
        if (entries != other.entries) return false

        return true
    }

    override fun hashCode(): Int {
        var result = seed
        result = 31 * result + entries.hashCode()
        return result
    }
}