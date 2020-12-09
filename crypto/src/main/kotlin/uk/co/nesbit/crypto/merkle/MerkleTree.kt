package uk.co.nesbit.crypto.merkle

import uk.co.nesbit.crypto.SecureHash

class MerkleTree(
    val leaves: List<ByteArray>,
    val digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider
) {
    init {
        require(leaves.isNotEmpty()) { "Merkle tree must have at least one item" }
    }

    companion object {
        fun nextHigherPower2(value: Int): Int {
            require(value > 0) { "nextHigherPower2 requires positive value" }
            require(value <= 0x40000000) { "nextHigherPower2 requires smaller value" }
            var v = value - 1
            v = v or (v ushr 1)
            v = v or (v ushr 2)
            v = v or (v ushr 4)
            v = v or (v ushr 8)
            v = v or (v ushr 16)
            return v + 1
        }

        fun treeDepth(size: Int): Int {
            val zeros = nextHigherPower2(size).countLeadingZeroBits()
            return 31 - zeros
        }

        //Based upon RFC6962 and https://github.com/openregister/verifiable-log
        fun verifyConsistencyProof(
            oldTreeSize: Int,
            oldRoot: SecureHash,
            newTreeSize: Int,
            newRoot: SecureHash,
            consistencyProof: List<SecureHash>,
            digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider
        ): Boolean {
            require(oldTreeSize > 0 && newTreeSize > 0) {
                "sizes must be positive"
            }
            require(oldTreeSize <= newTreeSize) {
                "first parameter must be less than or equal to second"
            }
            if (oldTreeSize == newTreeSize) {
                return oldRoot == newRoot && consistencyProof.isEmpty()
            }
            val computedOldRoot = oldRootHashFromConsistencyProof(
                oldTreeSize,
                newTreeSize,
                consistencyProof.toMutableList(),
                oldRoot,
                digestProvider
            )
            val computedNewRoot = newRootHashFromConsistencyProof(
                oldTreeSize,
                newTreeSize,
                consistencyProof.toMutableList(),
                oldRoot,
                digestProvider
            )
            return computedOldRoot == oldRoot && computedNewRoot == newRoot
        }

        private fun newRootHashFromConsistencyProof(
            low: Int,
            high: Int,
            consistencyProof: MutableList<SecureHash>,
            oldRoot: SecureHash,
            digestProvider: MerkleTreeHashDigestProvider
        ): Any {
            return rootHashFromConsistencyProof(
                low,
                high,
                0,
                consistencyProof,
                oldRoot,
                true,
                true,
                digestProvider
            )
        }

        private fun oldRootHashFromConsistencyProof(
            low: Int,
            high: Int,
            consistencyProof: MutableList<SecureHash>,
            oldRoot: SecureHash,
            digestProvider: MerkleTreeHashDigestProvider
        ): Any {
            return rootHashFromConsistencyProof(
                low,
                high,
                0,
                consistencyProof,
                oldRoot,
                false,
                true,
                digestProvider
            )
        }

        private fun rootHashFromConsistencyProof(
            low: Int,
            high: Int,
            depth: Int,
            consistencyProof: MutableList<SecureHash>,
            oldRoot: SecureHash,
            computeNewRoot: Boolean,
            startFromOldRoot: Boolean,
            digestProvider: MerkleTreeHashDigestProvider
        ): SecureHash {
            if (low == high) {
                return if (startFromOldRoot) {
                    // this is the b == true case in RFC 6962
                    oldRoot
                } else {
                    consistencyProof.removeAt(consistencyProof.size - 1)
                }
            }
            val k = nextHigherPower2(high) / 2
            val nextHash = consistencyProof.removeAt(consistencyProof.size - 1)
            return if (low <= k) {
                val leftChild = rootHashFromConsistencyProof(
                    low,
                    k,
                    depth + 1,
                    consistencyProof,
                    oldRoot,
                    computeNewRoot,
                    startFromOldRoot,
                    digestProvider
                )
                if (computeNewRoot) {
                    digestProvider.nodeHash(depth, leftChild, nextHash)
                } else {
                    leftChild
                }
            } else {
                val rightChild = rootHashFromConsistencyProof(
                    low - k,
                    high - k,
                    depth + 1,
                    consistencyProof,
                    oldRoot,
                    computeNewRoot,
                    false,
                    digestProvider
                )
                digestProvider.nodeHash(depth, nextHash, rightChild)
            }
        }
    }

    private val leafHashes: List<SecureHash> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        leaves.mapIndexed { index, bytes ->
            val nonce = digestProvider.leafNonce(index)
            digestProvider.leafHash(index, nonce, bytes)
        }
    }

    private val supportsTreeAppend: Boolean by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val hash1 = digestProvider.nodeHash(0, leafHashes.first(), leafHashes.first())
        val hash2 = digestProvider.nodeHash(1, leafHashes.first(), leafHashes.first())
        (hash1 == hash2) // log proofs require that node hash doesn't change with depth
    }

    private val nodeHashes: List<List<SecureHash>> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val hashSet = mutableListOf<List<SecureHash>>()
        var hashes = leafHashes
        hashSet += hashes
        var depthCounter = depth
        while (hashes.size > 1) {
            --depthCounter
            val nodeHashes = mutableListOf<SecureHash>()
            for (i in hashes.indices step 2) {
                if (i <= hashes.size - 2) {
                    nodeHashes += digestProvider.nodeHash(depthCounter, hashes[i], hashes[i + 1])
                }
            }
            if ((hashes.size and 1) == 1) {
                nodeHashes += hashes.last()
            }
            hashes = nodeHashes
            hashSet += hashes
        }
        require(depthCounter == 0) { "Sanity check root is at depth 0" }
        hashSet
    }

    val depth: Int by lazy(LazyThreadSafetyMode.PUBLICATION) {
        treeDepth(leaves.size)
    }

    val root: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        nodeHashes.last().single()
    }

    fun createAuditProof(leafIndices: List<Int>): MerkleProof {
        require(leafIndices.isNotEmpty()) { "Proof requires at least one leaf" }
        require(leafIndices.all { it >= 0 && it < leaves.size }) { "Leaf indices out of bounds" }
        var inPath = List(leaves.size) { it in leafIndices }
        val outputHashes = mutableListOf<SecureHash>()
        var level = 0
        while (inPath.size > 1) {
            val newInPath = mutableListOf<Boolean>()
            for (i in inPath.indices step 2) {
                if (i <= inPath.size - 2) {
                    newInPath += inPath[i] || inPath[i + 1]
                    if (!inPath[i] && inPath[i + 1]) {
                        outputHashes += nodeHashes[level][i]
                    } else if (inPath[i] && !inPath[i + 1]) {
                        outputHashes += nodeHashes[level][i + 1]
                    }
                }
            }
            if ((inPath.size and 1) == 1) {
                newInPath += inPath.last()
            }
            inPath = newInPath
            ++level
        }
        require(level == depth) { "Sanity check calc" }
        return MerkleProof(
            leaves.size,
            leafIndices.sorted().map { IndexedMerkleLeaf(it, digestProvider.leafNonce(it), leaves[it].copyOf()) },
            outputHashes
        )
    }

    fun consistencyProof(oldTreeSize: Int): List<SecureHash> {
        require(supportsTreeAppend) {
            "Hashing does not support merkle log append"
        }
        require(oldTreeSize > 0) {
            "sizes must be positive"
        }
        require(oldTreeSize <= leaves.size) {
            "first parameter must be less than or equal to second"
        }
        return subtreeConsistencyProof(oldTreeSize, leaves.size, 0, true)
    }

    private fun subtreeHash(start: Int, size: Int, depth: Int): SecureHash {
        require(size >= 1) {
            "empty range not allowed"
        }
        require(start >= 0 && start < leaves.size) {
            "Invalid start index"
        }
        return if (size == 1) {
            leafHashes[start]
        } else {
            val balanced = nextHigherPower2(size) / 2
            val left = subtreeHash(start, balanced, depth + 1)
            val right = subtreeHash(start + balanced, size - balanced, depth + 1)
            digestProvider.nodeHash(depth, left, right)
        }
    }

    //Based upon RFC6962 and https://github.com/openregister/verifiable-log
    private fun subtreeConsistencyProof(
        low: Int,
        high: Int,
        start: Int,
        startFromOldRoot: Boolean
    ): List<SecureHash> {
        if (low == high) {
            if (startFromOldRoot) {
                // this is the b == true case in RFC 6962
                return emptyList()
            }
            return listOf(subtreeHash(start, high, 0))
        }
        val k = nextHigherPower2(high) / 2
        return if (low <= k) {
            val subtreeConsistencySet = subtreeConsistencyProof(low, k, start, startFromOldRoot)
            subtreeConsistencySet + subtreeHash(start + k, high - k, 0)
        } else {
            val subtreeConsistencySet = subtreeConsistencyProof(low - k, high - k, start + k, false)
            subtreeConsistencySet + subtreeHash(start, k, 0)
        }
    }
}

