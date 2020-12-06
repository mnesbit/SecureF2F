package uk.co.nesbit.crypto.setsync

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.MurmurHash3

class InvertibleBloomEntry(
    var key: Int,
    var hash: Int,
    var count: Int
) : AvroConvertible {
    constructor(ibfEntryRecord: GenericRecord) : this(
        ibfEntryRecord.getTyped("key"),
        ibfEntryRecord.getTyped("hash"),
        ibfEntryRecord.getTyped("count")
    )

    constructor() : this(0, 0, 0)

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val ibfEntrySchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("invertiblebloomentry.avsc"))

        fun deserialize(bytes: ByteArray): InvertibleBloomEntry {
            val ibfEntryRecord = ibfEntrySchema.deserialize(bytes)
            return InvertibleBloomEntry(ibfEntryRecord)
        }
    }

    val isPure: Boolean get() = ((count == 1 || count == -1) && hash == calcHash(key))
    val isEmpty: Boolean get() = (count == 0 && hash == 0 && key == 0)

    fun add(newKey: Int) {
        val entryHash = calcHash(newKey)
        key = key xor newKey
        hash = hash xor entryHash
        ++count
    }

    fun sub(newKey: Int) {
        val entryHash = calcHash(newKey)
        key = key xor newKey
        hash = hash xor entryHash
        --count
    }

    private fun calcHash(newKey: Int) = MurmurHash3.hash32(newKey.toLong() + 0x100000000L)

    fun diff(other: InvertibleBloomEntry): InvertibleBloomEntry {
        return InvertibleBloomEntry(
            key xor other.key,
            hash xor other.hash,
            count - other.count
        )
    }

    override fun toGenericRecord(): GenericRecord {
        val ibfEntryRecord = GenericData.Record(ibfEntrySchema)
        ibfEntryRecord.putTyped("key", key)
        ibfEntryRecord.putTyped("hash", hash)
        ibfEntryRecord.putTyped("count", count)
        return ibfEntryRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as InvertibleBloomEntry

        if (key != other.key) return false
        if (hash != other.hash) return false
        if (count != other.count) return false

        return true
    }

    override fun hashCode(): Int {
        var result = key
        result = 31 * result + hash
        result = 31 * result + count
        return result
    }


}