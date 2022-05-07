package uk.co.nesbit.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.merkle.*
import uk.co.nesbit.crypto.merkle.impl.MerkleProofImpl
import uk.co.nesbit.crypto.merkle.impl.MerkleTreeImpl
import kotlin.experimental.xor
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class MerkleTreeTest {
    @Test
    fun `next power tests`() {
        assertEquals(1, MerkleTreeImpl.nextHigherPower2(1))
        assertEquals(2, MerkleTreeImpl.nextHigherPower2(2))
        assertEquals(4, MerkleTreeImpl.nextHigherPower2(3))
        assertEquals(0x20000, MerkleTreeImpl.nextHigherPower2(0x12345))
        assertEquals(0x40000000, MerkleTreeImpl.nextHigherPower2(0x30000000))
        assertFailsWith<IllegalArgumentException> { MerkleTreeImpl.nextHigherPower2(0) }
        assertFailsWith<IllegalArgumentException> { MerkleTreeImpl.nextHigherPower2(-5) }
        assertFailsWith<IllegalArgumentException> { MerkleTreeImpl.nextHigherPower2(0x7FFFFFFF) }
    }

    private fun MerkleTree.calcLeafHash(index: Int): SecureHash {
        return digestProvider.leafHash(
            index,
            digestProvider.leafNonce(index),
            leaves[index]
        )
    }

    @Test
    fun `tree test 1 node`() {
        val leafData = (0..0).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        assertEquals(leaf0, root)
    }

    @Test
    fun `tree test 2 node`() {
        val leafData = (0..1).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, leaf0, leaf1)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 3 node`() {
        val leafData = (0..2).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val leaf2 = merkleTree.calcLeafHash(2)
        val node1 = merkleTree.digestProvider.nodeHash(1, leaf0, leaf1)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node1, leaf2)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 4 node`() {
        val leafData = (0..3).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val leaf2 = merkleTree.calcLeafHash(2)
        val leaf3 = merkleTree.calcLeafHash(3)
        val node1 = merkleTree.digestProvider.nodeHash(1, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(1, leaf2, leaf3)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node1, node2)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 5 node`() {
        val leafData = (0..4).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val leaf2 = merkleTree.calcLeafHash(2)
        val leaf3 = merkleTree.calcLeafHash(3)
        val leaf4 = merkleTree.calcLeafHash(4)
        val node1 = merkleTree.digestProvider.nodeHash(2, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(2, leaf2, leaf3)
        val node3 = merkleTree.digestProvider.nodeHash(1, node1, node2)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node3, leaf4)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 6 node`() {
        val leafData = (0..5).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val leaf2 = merkleTree.calcLeafHash(2)
        val leaf3 = merkleTree.calcLeafHash(3)
        val leaf4 = merkleTree.calcLeafHash(4)
        val leaf5 = merkleTree.calcLeafHash(5)
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
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val leaf2 = merkleTree.calcLeafHash(2)
        val leaf3 = merkleTree.calcLeafHash(3)
        val leaf4 = merkleTree.calcLeafHash(4)
        val leaf5 = merkleTree.calcLeafHash(5)
        val leaf6 = merkleTree.calcLeafHash(6)
        val node1 = merkleTree.digestProvider.nodeHash(3, leaf0, leaf1)
        val node2 = merkleTree.digestProvider.nodeHash(3, leaf2, leaf3)
        val node3 = merkleTree.digestProvider.nodeHash(2, leaf4, leaf5)
        val node4 = merkleTree.digestProvider.nodeHash(2, node1, node2)
        val node5 = merkleTree.digestProvider.nodeHash(1, node3, leaf6)
        val manualRoot = merkleTree.digestProvider.nodeHash(0, node4, node5)
        assertEquals(manualRoot, root)
    }

    @Test
    fun `tree test 8 node`() {
        val leafData = (0..7).map { it.toByteArray() }
        val merkleTree = MerkleTree.createMerkleTree(leafData)
        val root = merkleTree.root
        val leaf0 = merkleTree.calcLeafHash(0)
        val leaf1 = merkleTree.calcLeafHash(1)
        val leaf2 = merkleTree.calcLeafHash(2)
        val leaf3 = merkleTree.calcLeafHash(3)
        val leaf4 = merkleTree.calcLeafHash(4)
        val leaf5 = merkleTree.calcLeafHash(5)
        val leaf6 = merkleTree.calcLeafHash(6)
        val leaf7 = merkleTree.calcLeafHash(7)
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
        for (treeSize in 1 until 16) {
            val leafData = (0 until treeSize).map { it.toByteArray() }
            val merkleTree = MerkleTree.createMerkleTree(leafData, NonceHashDigestProvider())
            val root = merkleTree.root
            for (i in 1 until (1 shl treeSize)) {
                val powerSet = (0 until treeSize).filter { (i and (1 shl it)) != 0 }
                val proof = merkleTree.createAuditProof(powerSet)
                val serialised = proof.serialize()
                val deserialisedProof = MerkleProof.deserialize(serialised)
                assertEquals(proof, deserialisedProof)
                val result = deserialisedProof.verify(root, NonceHashDigestProvider.VERIFY_INSTANCE)
                assertEquals(true, result, "failed $powerSet")
                for (leaf in proof.leaves) {
                    val data = leaf.leafData
                    data[0] = data[0] xor 1
                    assertEquals(false, proof.verify(root, NonceHashDigestProvider.VERIFY_INSTANCE))
                    data[0] = data[0] xor 1
                }
                for (hash in proof.hashes) {
                    val data = hash.bytes
                    data[0] = data[0] xor 1
                    assertEquals(false, proof.verify(root, NonceHashDigestProvider.VERIFY_INSTANCE))
                    data[0] = data[0] xor 1
                }
                val badProof1: MerkleProof =
                    MerkleProofImpl(proof.treeSize, proof.leaves, proof.hashes + SecureHash.EMPTY_HASH)
                assertEquals(false, badProof1.verify(root, NonceHashDigestProvider.VERIFY_INSTANCE))
                if (proof.hashes.size > 1) {
                    val badProof2: MerkleProof =
                        MerkleProofImpl(proof.treeSize, proof.leaves, proof.hashes.take(proof.hashes.size - 1))
                    assertEquals(false, badProof2.verify(root, NonceHashDigestProvider.VERIFY_INSTANCE))
                }
                if (proof.leaves.size > 1) {
                    val badProof3: MerkleProof =
                        MerkleProofImpl(proof.treeSize, proof.leaves.take(proof.leaves.size - 1), proof.hashes)
                    assertEquals(false, badProof3.verify(root, NonceHashDigestProvider.VERIFY_INSTANCE))
                }
            }
        }
    }

    @Test
    fun `nonce digest serialisation test`() {
        val provider1 = NonceHashDigestProvider()
        val serialised = provider1.serialize()
        val deserialised = NonceHashDigestProvider.deserialize(serialised)
        assertEquals(provider1, deserialised)
        assertArrayEquals(provider1.leafNonce(1), deserialised.leafNonce(1))
        assertEquals(false, provider1.leafNonce(0).contentEquals(provider1.leafNonce(1)))
        assertEquals(false, provider1.leafNonce(0).contentEquals(provider1.leafNonce(1)))
    }

    @Test
    fun `merkle consistency test`() {
        val leafData = (0 until 32).map { it.toByteArray() }
        for (newSize in 1..32) {
            for (oldSize in 1..newSize) {
                val merkleTree1 = MerkleTree.createMerkleTree(leafData.subList(0, oldSize))
                val merkleTree2 = MerkleTree.createMerkleTree(leafData.subList(0, newSize))
                val proof = merkleTree2.consistencyProof(oldSize)
                val result =
                    MerkleTree.verifyConsistencyProof(oldSize, merkleTree1.root, newSize, merkleTree2.root, proof)
                assertEquals(true, result)
            }
        }
        assertFailsWith<java.lang.IllegalArgumentException> {
            val unsupportedTree = MerkleTree.createMerkleTree(leafData, NonceHashDigestProvider())
            unsupportedTree.consistencyProof(3)
        }
    }

    @Test
    fun `test different merkle tree types give different hashes`() {
        val leafData = (0 until 16).map { it.toByteArray() }
        val leafList = listOf(1, 7, 11)
        val merkleTreeDefault = MerkleTree.createMerkleTree(leafData, DefaultHashDigestProvider)
        val proof1 = merkleTreeDefault.createAuditProof(leafList)
        assertEquals(true, proof1.verify(merkleTreeDefault.root, DefaultHashDigestProvider))
        val tweakedHash = TweakableHashDigestProvider(ByteArray(4) { 0x12 }, ByteArray(4) { 0x34 })
        val merkleTreeTweaked = MerkleTree.createMerkleTree(leafData, tweakedHash)
        val proof2 = merkleTreeTweaked.createAuditProof(leafList)
        assertEquals(true, proof2.verify(merkleTreeTweaked.root, tweakedHash))
        val nonceMerkleTree1 = MerkleTree.createMerkleTree(leafData, NonceHashDigestProvider())
        val proof3 = nonceMerkleTree1.createAuditProof(leafList)
        assertEquals(true, proof3.verify(nonceMerkleTree1.root, NonceHashDigestProvider.VERIFY_INSTANCE))
        val nonceMerkleTree2 = MerkleTree.createMerkleTree(leafData, NonceHashDigestProvider())
        val proof4 = nonceMerkleTree2.createAuditProof(leafList)
        assertEquals(true, proof4.verify(nonceMerkleTree2.root, NonceHashDigestProvider.VERIFY_INSTANCE))
        val roots = setOf(merkleTreeDefault.root, merkleTreeTweaked.root, nonceMerkleTree1.root, nonceMerkleTree2.root)
        assertEquals(4, roots.size)
        assertNotEquals(proof3, proof4)
    }
}