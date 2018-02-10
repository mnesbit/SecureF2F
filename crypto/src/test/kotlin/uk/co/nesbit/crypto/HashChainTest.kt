package uk.co.nesbit.crypto

import org.junit.Assert
import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import java.util.*
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HashChainTest {
    @Test
    fun `version chain test`() {
        val rand = newSecureRandom()
        val id1 = SphinxIdentityKeyPair.generateKeyPair(rand, "Alice")
        val id2 = SphinxIdentityKeyPair.generateKeyPair(rand, "Bob")
        val chainValue1 = id1.getVersionedId(0)
        Assert.assertEquals(id1.hashChain.targetHash, chainValue1.currentVersion.chainHash)
        Assert.assertEquals(0, chainValue1.currentVersion.version)
        Assert.assertEquals(id1.public, chainValue1.identity)
        val chainValue2a = id1.getVersionedId(100)
        val chainValue2b = id1.getVersionedId(100)
        Assert.assertEquals(chainValue2a, chainValue2b)
        Assert.assertEquals(100, chainValue2a.currentVersion.version)
        Assert.assertEquals(id1.public, chainValue2a.identity)
        Assert.assertTrue(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        Assert.assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 99))
        Assert.assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 101))
        Assert.assertFalse(id2.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getVersionedId(99)
        }
        val chainValue3 = id1.getVersionedId(101)
        Assert.assertEquals(101, chainValue3.currentVersion.version)
        Assert.assertEquals(id1.public, chainValue3.identity)
        Assert.assertTrue(id1.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
        Assert.assertFalse(id2.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
    }

    @Test
    fun `serialization test`() {
        val chain = PebbledHashChain.generateChain("Test".toByteArray())
        val publicChain = chain.public
        val serializedChain = publicChain.serialize()
        val deserializedChain = HashChainPublic.deserialize(serializedChain)
        assertEquals(publicChain, deserializedChain)
        val serializedChainRecord = publicChain.toGenericRecord()
        val deserializedChain2 = HashChainPublic(serializedChainRecord)
        assertEquals(publicChain, deserializedChain2)
        val id1 = chain.getSecureVersion(100)
        assertTrue(deserializedChain.verifyChainValue(id1.chainHash, 100))
        assertFalse(deserializedChain.verifyChainValue(id1.chainHash, 99))
    }

    @Test
    fun `pebble vs simple test`() {
        val dummySecureRandom = Random()
        dummySecureRandom.setSeed(100)
        val keyMaterial = "Test".toByteArray()
        val pebbledHashChain = PebbledHashChain.generateChain(keyMaterial, dummySecureRandom)
        dummySecureRandom.setSeed(100)
        val originalHashChain = SimpleHashChainPrivate.generateChain(keyMaterial, dummySecureRandom)
        assertEquals(originalHashChain.secureVersion, pebbledHashChain.secureVersion)
        assertEquals(originalHashChain.targetHash, pebbledHashChain.targetHash)
        assertEquals(originalHashChain.public, pebbledHashChain.public)
        for (i in 0 until 50) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
        }
        for (i in 150 until 160 step 3) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
        }
        for (i in 2000 until 2010) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
        }
        for (i in HashChainPublic.MAX_CHAIN_LENGTH - 3..HashChainPublic.MAX_CHAIN_LENGTH) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
        }
    }
}