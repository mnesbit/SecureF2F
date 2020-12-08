package uk.co.nesbit.crypto.merkle

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped

class IndexedMerkleLeaf(
    val index: Int,
    val nonce: ByteArray?,
    val leafData: ByteArray
) : AvroConvertible {
    constructor(leafRecord: GenericRecord) : this(
        leafRecord.getTyped("index"),
        leafRecord.getTyped("nonce"),
        leafRecord.getTyped("leafData")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val indexedMerkleLeafSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("indexedmerkleleaf.avsc"))

        fun deserialize(bytes: ByteArray): IndexedMerkleLeaf {
            val leafRecord = indexedMerkleLeafSchema.deserialize(bytes)
            return IndexedMerkleLeaf(leafRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val leafRecord = GenericData.Record(indexedMerkleLeafSchema)
        leafRecord.putTyped("index", index)
        leafRecord.putTyped("nonce", nonce)
        leafRecord.putTyped("leafData", leafData)
        return leafRecord
    }

    override fun toString(): String {
        return "Leaf($index)[${leafData.size} bytes]"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IndexedMerkleLeaf

        if (index != other.index) return false
        if (nonce != null) {
            if (other.nonce == null) return false
            if (!nonce.contentEquals(other.nonce)) return false
        } else if (other.nonce != null) return false
        if (!leafData.contentEquals(other.leafData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = index
        result = 31 * result + (nonce?.contentHashCode() ?: 0)
        result = 31 * result + leafData.contentHashCode()
        return result
    }

}