package uk.co.nesbit.crypto.merkle

import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.merkle.impl.MerkleTreeImpl

interface MerkleTree {
    companion object {
        @JvmStatic
        fun createMerkleTree(
            leaves: List<ByteArray>,
            digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider
        ): MerkleTree = MerkleTreeImpl(leaves, digestProvider)

        //Based upon RFC6962 and https://github.com/openregister/verifiable-log
        @JvmStatic
        fun verifyConsistencyProof(
            oldTreeSize: Int,
            oldRoot: SecureHash,
            newTreeSize: Int,
            newRoot: SecureHash,
            consistencyProof: List<SecureHash>,
            digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider
        ): Boolean = MerkleTreeImpl.verifyConsistencyProof(
            oldTreeSize,
            oldRoot,
            newTreeSize,
            newRoot,
            consistencyProof,
            digestProvider
        )
    }

    val leaves: List<ByteArray>
    val digestProvider: MerkleTreeHashDigestProvider
    val depth: Int
    val root: SecureHash

    fun createAuditProof(leafIndices: List<Int>): MerkleProof

    fun consistencyProof(oldTreeSize: Int): List<SecureHash>
}