package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.network.api.tree.TreeState
import uk.co.nesbit.network.api.tree.TreeStatus
import kotlin.experimental.xor
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class TreeEngineTests {
    @Test
    fun `TreeState tests`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPair1 = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPair2 = SphinxIdentityKeyPair.generateKeyPair(random)
        val ids = listOf(sphinxIdentityKeyPair1.public, sphinxIdentityKeyPair2.public)
        for (state in TreeStatus.values()) {
            for (len in 0 until ids.size) {
                val treeState = TreeState(1L, 2L, state, ids.take(len))
                assertEquals(len, treeState.depth)
                val serialized = treeState.serialize()
                val deserialized = TreeState.deserialize(serialized)
                assertEquals(treeState, deserialized)
                val deserialized2 = TreeState.tryDeserialize(serialized)
                assertEquals(treeState, deserialized2)
                serialized[0] = serialized[0] xor 1
                assertNull(TreeState.tryDeserialize(serialized))
                val treeState2 = TreeState(3L, null, state, ids.take(len))
                assertEquals(len, treeState2.depth)
                val serialized2 = treeState2.serialize()
                val deserialized3 = TreeState.deserialize(serialized2)
                assertEquals(treeState2, deserialized3)
            }
        }
    }

    @Test
    fun `test path compare`() {
        val random = newSecureRandom()
        val ids = (0..4).map { SphinxIdentityKeyPair.generateKeyPair(random).public }.sortedByDescending { it.id }
        val list1 = listOf(ids[0])
        val list2 = listOf(ids[1])
        val list3 = listOf(ids[0], ids[1])
        val list4 = listOf(ids[0], ids[2])
        val list5 = listOf(ids[1], ids[2])
        val list6 = listOf(ids[1], ids[2], ids[3])
        val list7 = listOf(ids[1], ids[3], ids[2])
        val list8 = listOf(ids[0], ids[1], ids[2])
        assertEquals(0, TreeState.comparePath(list1, list1))
        assertEquals(0, TreeState.comparePath(list2, list2))
        assertEquals(0, TreeState.comparePath(list7, list7))
        assertTrue(TreeState.comparePath(list1, list2) > 0) // best id
        assertTrue(TreeState.comparePath(list3, list4) > 0) // best id
        assertTrue(TreeState.comparePath(list6, list7) > 0) // best id
        assertTrue(TreeState.comparePath(list1, list3) > 0) // shorter same root
        assertTrue(TreeState.comparePath(list5, list6) > 0) // shorter same root
        assertTrue(TreeState.comparePath(list8, list2) > 0) // better root
        assertTrue(TreeState.comparePath(list4, list5) > 0) // better root
    }
}