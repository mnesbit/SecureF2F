package uk.co.nesbit.crypto

import org.junit.Test
import kotlin.experimental.xor
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class MerkleTreeTest {
    @Test
    fun `next power tests`() {
        assertEquals(1, MerkleTree.nextHigherPower2(1))
        assertEquals(2, MerkleTree.nextHigherPower2(2))
        assertEquals(4, MerkleTree.nextHigherPower2(3))
        assertEquals(0x20000, MerkleTree.nextHigherPower2(0x12345))
        assertEquals(0x40000000, MerkleTree.nextHigherPower2(0x30000000))
        assertFailsWith<IllegalArgumentException> { MerkleTree.nextHigherPower2(0) }
        assertFailsWith<IllegalArgumentException> { MerkleTree.nextHigherPower2(-5) }
        assertFailsWith<IllegalArgumentException> { MerkleTree.nextHigherPower2(0x7FFFFFFF) }
    }

    @Test
    fun `next lower power tests`() {
        assertEquals(1, MerkleTree.nextLowerPower2(1))
        assertEquals(2, MerkleTree.nextLowerPower2(2))
        assertEquals(2, MerkleTree.nextLowerPower2(3))
        assertEquals(0x10000, MerkleTree.nextLowerPower2(0x12345))
        assertEquals(0x20000000, MerkleTree.nextLowerPower2(0x30000000))
        assertFailsWith<IllegalArgumentException> { MerkleTree.nextLowerPower2(0) }
        assertFailsWith<IllegalArgumentException> { MerkleTree.nextLowerPower2(-5) }
        assertFailsWith<IllegalArgumentException> { MerkleTree.nextLowerPower2(0x7FFFFFFF) }
    }

    @Test
    fun `tree test 1 node`() {
        val leafData = (0..0).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        assertEquals(leaf0, root)
    }

    @Test
    fun `tree test 2 node`() {
        val leafData = (0..1).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val manualRoot = merkleTree.digestProvider.nodeHash(0, leaf0, leaf1)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 3 node`() {
        val leafData = (0..2).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val leaf2 = merkleTree.digestProvider.leafHash(2, leafData[2])
        val node1 = merkleTree.digestProvider.nodeHash(1, leaf0, leaf1)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node1, leaf2)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 4 node`() {
        val leafData = (0..3).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val leaf2 = merkleTree.digestProvider.leafHash(2, leafData[2])
        val leaf3 = merkleTree.digestProvider.leafHash(3, leafData[3])
        val node1 = merkleTree.digestProvider.nodeHash(1, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(1, leaf2, leaf3)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node1, node2)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 5 node`() {
        val leafData = (0..4).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val leaf2 = merkleTree.digestProvider.leafHash(2, leafData[2])
        val leaf3 = merkleTree.digestProvider.leafHash(3, leafData[3])
        val leaf4 = merkleTree.digestProvider.leafHash(4, leafData[4])
        val node1 = merkleTree.digestProvider.nodeHash(2, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(2, leaf2, leaf3)
        val node3 = merkleTree.digestProvider.nodeHash(1, node1, node2)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node3, leaf4)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 6 node`() {
        val leafData = (0..5).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val leaf2 = merkleTree.digestProvider.leafHash(2, leafData[2])
        val leaf3 = merkleTree.digestProvider.leafHash(3, leafData[3])
        val leaf4 = merkleTree.digestProvider.leafHash(4, leafData[4])
        val leaf5 = merkleTree.digestProvider.leafHash(5, leafData[5])
        val node1 = merkleTree.digestProvider.nodeHash(2, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(2, leaf2, leaf3)
        val node3 = merkleTree.digestProvider.nodeHash(1, node1, node2)
        val node4 = merkleTree.digestProvider.nodeHash(1, leaf4, leaf5)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node3, node4)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 7 node`() {
        val leafData = (0..6).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val leaf2 = merkleTree.digestProvider.leafHash(2, leafData[2])
        val leaf3 = merkleTree.digestProvider.leafHash(3, leafData[3])
        val leaf4 = merkleTree.digestProvider.leafHash(4, leafData[4])
        val leaf5 = merkleTree.digestProvider.leafHash(5, leafData[5])
        val leaf6 = merkleTree.digestProvider.leafHash(6, leafData[6])
        val node1 = merkleTree.digestProvider.nodeHash(3, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(3, leaf2, leaf3)
        val node3 = merkleTree.digestProvider.nodeHash(2, node1, node2)
        val node4 = merkleTree.digestProvider.nodeHash(2, leaf4, leaf5)
        val node5 = merkleTree.digestProvider.nodeHash(1, node3, node4)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node5, leaf6)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 8 node`() {
        val leafData = (0..7).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.digestProvider.leafHash(0, leafData[0])
        val leaf1 = merkleTree.digestProvider.leafHash(1, leafData[1])
        val leaf2 = merkleTree.digestProvider.leafHash(2, leafData[2])
        val leaf3 = merkleTree.digestProvider.leafHash(3, leafData[3])
        val leaf4 = merkleTree.digestProvider.leafHash(4, leafData[4])
        val leaf5 = merkleTree.digestProvider.leafHash(5, leafData[5])
        val leaf6 = merkleTree.digestProvider.leafHash(6, leafData[6])
        val leaf7 = merkleTree.digestProvider.leafHash(7, leafData[7])
        val node1 = merkleTree.digestProvider.nodeHash(2, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(2, leaf2, leaf3)
        val node3 = merkleTree.digestProvider.nodeHash(2, leaf4, leaf5)
        val node4 = merkleTree.digestProvider.nodeHash(2, leaf6, leaf7)
        val node5 = merkleTree.digestProvider.nodeHash(1, node1, node2)
        val node6 = merkleTree.digestProvider.nodeHash(1, node3, node4)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node5, node6)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `merkle proofs`() {
        val leafData = (0..12).map { it.toByteArray() }
        val merkleTree = MerkleTree(leafData)
        val root = merkleTree.root
        for (i in 1 until (1 shl 12)) {
            val powerSet = (0 until 12).filter { (i and (1 shl it)) != 0 }
            val proof = merkleTree.createProof(powerSet)
            assertEquals(true, proof.verify(root))
            for (leaf in proof.leaves) {
                val data = leaf.leafData
                data[0] = data[0] xor 1
                assertEquals(false, proof.verify(root))
                data[0] = data[0] xor 1
            }
            for (hash in proof.hashes) {
                val data = hash.bytes
                data[0] = data[0] xor 1
                assertEquals(false, proof.verify(root))
                data[0] = data[0] xor 1
            }
        }
    }
}