package uk.co.nesbit.crypto

import uk.co.nesbit.crypto.MerkleTree.Companion.nextLowerPower2
import uk.co.nesbit.crypto.MerkleTree.Companion.treeDepth

class MerkleTree(
    val leaves: List<ByteArray>,
    val digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider()
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

        fun isPowerOf2(value: Int): Boolean {
            require(value > 0) { "isPowerOf2 requires positive value" }
            return (value and (value - 1) == 0)
        }

        fun nextLowerPower2(value: Int): Int {
            if (isPowerOf2(value)) {
                return value
            }
            return nextHigherPower2(value) ushr 1
        }

        fun treeDepth(size: Int): Int {
            var depth = 0
            var count = size
            while (count > 1) {
                ++depth
                val balanced = nextLowerPower2(count)
                count -= balanced / 2
            }
            return depth
        }
    }

    private val leafHashes: List<SecureHash> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        leaves.mapIndexed { index, bytes -> digestProvider.leafHash(index, bytes) }
    }

    private val nodeHashes: List<List<SecureHash>> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val hashSet = mutableListOf<List<SecureHash>>()
        var hashes = leafHashes
        hashSet += hashes
        var depthCounter = depth
        while (hashes.size > 1) {
            --depthCounter
            val balanced = nextLowerPower2(hashes.size)
            val nodeHashes = mutableListOf<SecureHash>()
            for (i in 0 until balanced step 2) {
                nodeHashes += digestProvider.nodeHash(depthCounter, hashes[i], hashes[i + 1])
            }
            hashes = nodeHashes + hashes.subList(balanced, hashes.size)
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

    fun createProof(leafIndices: List<Int>): MerkleProof {
        require(leafIndices.isNotEmpty()) { "Proof requires at least one leaf" }
        require(leafIndices.all { it >= 0 && it < leaves.size }) { "Leaf indices out of bounds" }
        var inPath = List(leaves.size) { it in leafIndices }
        val outputHashes = mutableListOf<SecureHash>()
        var level = 0
        while (inPath.size > 1) {
            val balanced = nextLowerPower2(inPath.size)
            val newInPath = mutableListOf<Boolean>()
            for (i in 0 until balanced step 2) {
                newInPath += inPath[i] || inPath[i + 1]
                if (!inPath[i] && inPath[i + 1]) {
                    outputHashes += nodeHashes[level][i]
                } else if (inPath[i] && !inPath[i + 1]) {
                    outputHashes += nodeHashes[level][i + 1]
                }
            }
            inPath = newInPath + inPath.subList(balanced, inPath.size)
            ++level
        }
        require(level == depth) { "Sanity check calc" }
        return MerkleProof(
            leaves.size,
            leafIndices.sorted().map { IndexedLeaf(it, leaves[it].copyOf()) },
            outputHashes
        )
    }
}

class IndexedLeaf(val index: Int, val leafData: ByteArray) {
    override fun toString(): String {
        return "Leaf($index)[${leafData.size} bytes]"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as IndexedLeaf

        if (index != other.index) return false
        if (!leafData.contentEquals(other.leafData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = index
        result = 31 * result + leafData.contentHashCode()
        return result
    }
}

data class MerkleProof(
    val treeSize: Int,
    val leaves: List<IndexedLeaf>,
    val hashes: List<SecureHash>
) {
    fun verify(root: SecureHash, digestProvider: MerkleTreeHashDigestProvider = DefaultHashDigestProvider()): Boolean {
        if (leaves.isEmpty()) {
            return false
        }
        if (leaves.any { it.index < 0 && it.index >= leaves.size }) {
            return false
        }
        var hashIndex = 0
        val sortedLeaves = leaves.sortedBy { it.index }
        var nodeHashes = sortedLeaves.map { Pair(it.index, digestProvider.leafHash(it.index, it.leafData)) }
        var treeDepth = treeDepth(treeSize)
        var currentSize = treeSize
        while (currentSize > 1) {
            --treeDepth
            val balance = nextLowerPower2(currentSize)
            val newItems = mutableListOf<Pair<Int, SecureHash>>()
            var index = 0
            while (index < nodeHashes.size) {
                val item = nodeHashes[index]
                if (item.first < balance) {
                    if (hashIndex >= hashes.size) {
                        return false
                    }
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
                    if (item.first and 1 == 0) {
                        newItems += Pair(
                            item.first / 2,
                            digestProvider.nodeHash(treeDepth, item.second, hashes[hashIndex++])
                        )
                    } else {
                        newItems += Pair(
                            item.first / 2,
                            digestProvider.nodeHash(treeDepth, hashes[hashIndex++], item.second)
                        )
                    }
                } else {
                    newItems += Pair(item.first - (balance / 2), item.second)
                }
                ++index
            }
            currentSize -= balance / 2
            nodeHashes = newItems
        }
        if (hashIndex != hashes.size) {
            return false
        }
        return nodeHashes.single().second == root
    }
}