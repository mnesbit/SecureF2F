package uk.co.nesbit.crypto.merkle

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash

data class MerkleProof(
    val treeSize: Int,
    val leaves: List<IndexedMerkleLeaf>,
    val hashes: List<SecureHash>
) : AvroConvertible {
    constructor(proofRecord: GenericRecord) : this(
        proofRecord.getTyped("treeSize"),
        proofRecord.getObjectArray("leaves", ::IndexedMerkleLeaf),
        proofRecord.getObjectArray("hashes", ::SecureHash)
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val merkleProofSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    IndexedMerkleLeaf.indexedMerkleLeafSchema.fullName to IndexedMerkleLeaf.indexedMerkleLeafSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("merkleproof.avsc"))

        fun deserialize(bytes: ByteArray): MerkleProof {
            val proofRecord = merkleProofSchema.deserialize(bytes)
            return MerkleProof(proofRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val proofRecord = GenericData.Record(merkleProofSchema)
        proofRecord.putTyped("treeSize", treeSize)
        proofRecord.putObjectArray("leaves", leaves)
        proofRecord.putObjectArray("hashes", hashes)
        return proofRecord
    }

    fun verify(root: SecureHash, digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider()): Boolean {
        if (leaves.isEmpty()) {
            return false
        }
        if (leaves.any { it.index < 0 && it.index >= leaves.size }) {
            return false
        }
        if (leaves.map { it.index }.toSet().size != leaves.size) {
            return false
        }
        var hashIndex = 0
        val sortedLeaves = leaves.sortedBy { it.index }
        var nodeHashes = sortedLeaves.map { Pair(it.index, digestProvider.leafHash(it.index, it.nonce, it.leafData)) }
        var treeDepth = MerkleTree.treeDepth(treeSize)
        var currentSize = treeSize
        while (currentSize > 1) {
            if (nodeHashes.isEmpty()) {
                return false
            }
            --treeDepth
            val newItems = mutableListOf<Pair<Int, SecureHash>>()
            var index = 0
            while (index < nodeHashes.size) {
                val item = nodeHashes[index]
                if (item.first < currentSize and 0x7FFFFFFE) {
                    if (index < nodeHashes.size - 1) {
                        val next = nodeHashes[index + 1]
                        if (item.first xor next.first == 1) {
                            newItems += Pair(
                                item.first / 2,
                                digestProvider.nodeHash(treeDepth, item.second, next.second)
                            )
                            index += 2
                            continue
                        }
                    }
                    if (hashIndex >= hashes.size) {
                        return false
                    }
                    newItems += if (item.first and 1 == 0) {
                        Pair(
                            item.first / 2,
                            digestProvider.nodeHash(treeDepth, item.second, hashes[hashIndex++])
                        )
                    } else {
                        Pair(
                            item.first / 2,
                            digestProvider.nodeHash(treeDepth, hashes[hashIndex++], item.second)
                        )
                    }
                } else {
                    newItems += Pair((item.first + 1) / 2, item.second)
                }
                ++index
            }
            currentSize = (currentSize + 1) / 2
            nodeHashes = newItems
        }
        if (hashIndex != hashes.size) {
            return false
        }
        if (nodeHashes.size != 1) {
            return false
        }
        return nodeHashes.single().second == root
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as MerkleProof

        if (treeSize != other.treeSize) return false
        if (leaves != other.leaves) return false
        if (hashes != other.hashes) return false

        return true
    }

    override fun hashCode(): Int {
        var result = treeSize
        result = 31 * result + leaves.hashCode()
        result = 31 * result + hashes.hashCode()
        return result
    }
}