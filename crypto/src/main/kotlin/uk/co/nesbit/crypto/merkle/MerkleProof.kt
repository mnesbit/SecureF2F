package uk.co.nesbit.crypto.merkle

import org.apache.avro.Schema
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.merkle.impl.MerkleProofImpl

interface MerkleProof : AvroConvertible {
    companion object {
        val merkleProofSchema: Schema = MerkleProofImpl.merkleProofSchema

        @JvmStatic
        fun deserialize(bytes: ByteArray): MerkleProof = MerkleProofImpl.deserialize(bytes)

        @JvmStatic
        fun deserialize(genericRecord: GenericRecord): MerkleProof = MerkleProofImpl(genericRecord)
    }

    val treeSize: Int
    val leaves: List<IndexedMerkleLeaf>
    val hashes: List<SecureHash>

    fun verify(
        root: SecureHash,
        digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider
    ): Boolean
}