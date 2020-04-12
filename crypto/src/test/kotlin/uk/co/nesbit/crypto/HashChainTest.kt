package uk.co.nesbit.crypto

import org.junit.Assert.*
import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import java.util.*
import kotlin.test.assertFailsWith

class HashChainTest {
    @Test
    fun `version chain test`() {
        val rand = newSecureRandom()
        val id1 = SphinxIdentityKeyPair.generateKeyPair(rand, "Alice")
        val id2 = SphinxIdentityKeyPair.generateKeyPair(rand, "Bob")
        val chainValue1 = id1.getVersionedId(0)
        assertEquals(id1.hashChain.targetHash, chainValue1.currentVersion.chainHash)
        assertEquals(0, chainValue1.currentVersion.version)
        assertEquals(HashChainPublic.MAX_CHAIN_LENGTH, chainValue1.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue1.identity)
        val chainValue2a = id1.getVersionedId(100)
        val chainValue2b = id1.getVersionedId(100)
        assertEquals(chainValue2a, chainValue2b)
        assertEquals(100, chainValue2a.currentVersion.version)
        assertEquals(HashChainPublic.MAX_CHAIN_LENGTH, chainValue2a.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue2a.identity)
        assertTrue(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 99))
        assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 101))
        assertFalse(id2.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getVersionedId(99)
        }
        val chainValue3 = id1.getVersionedId(101)
        assertEquals(101, chainValue3.currentVersion.version)
        assertEquals(HashChainPublic.MAX_CHAIN_LENGTH, chainValue3.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue3.identity)
        assertTrue(id1.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
        assertFalse(id2.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
    }

    @Test
    fun `short version chain test`() {
        val rand = newSecureRandom()
        val maxVersion = 128
        val id1 = SphinxIdentityKeyPair.generateKeyPair(rand, "Alice", maxVersion = maxVersion)
        val id2 = SphinxIdentityKeyPair.generateKeyPair(rand, "Bob", maxVersion = maxVersion)
        val chainValue1 = id1.getVersionedId(0)
        assertEquals(id1.hashChain.targetHash, chainValue1.currentVersion.chainHash)
        assertEquals(0, chainValue1.currentVersion.version)
        assertEquals(0, chainValue1.currentVersion.minVersion)
        assertEquals(maxVersion, chainValue1.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue1.identity)
        val chainValue2a = id1.getVersionedId(100)
        val chainValue2b = id1.getVersionedId(100)
        assertEquals(chainValue2a, chainValue2b)
        assertEquals(100, chainValue2a.currentVersion.version)
        assertEquals(0, chainValue2a.currentVersion.minVersion)
        assertEquals(maxVersion, chainValue2a.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue2a.identity)
        assertTrue(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 99))
        assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 101))
        assertFalse(id2.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getVersionedId(99)
        }
        val chainValue3 = id1.getVersionedId(101)
        assertEquals(101, chainValue3.currentVersion.version)
        assertEquals(0, chainValue3.currentVersion.minVersion)
        assertEquals(maxVersion, chainValue3.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue3.identity)
        assertTrue(id1.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
        assertFalse(id2.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getVersionedId(maxVersion + 1)
        }
    }

    @Test
    fun `short version chain test non-zero minimum`() {
        val rand = newSecureRandom()
        val minVersion = 10
        val maxVersion = 128
        val id1 = SphinxIdentityKeyPair.generateKeyPair(rand, "Alice", maxVersion = maxVersion, minVersion = minVersion)
        val id2 = SphinxIdentityKeyPair.generateKeyPair(rand, "Bob", maxVersion = maxVersion, minVersion = minVersion)
        val chainValue1 = id1.getVersionedId(minVersion)
        assertEquals(minVersion, chainValue1.currentVersion.version)
        assertEquals(minVersion, chainValue1.currentVersion.minVersion)
        assertEquals(maxVersion, chainValue1.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue1.identity)
        assertTrue(id1.public.verifyChainValue(chainValue1.currentVersion))
        val chainValue2a = id1.getVersionedId(100)
        val chainValue2b = id1.getVersionedId(100)
        assertEquals(chainValue2a, chainValue2b)
        assertEquals(100, chainValue2a.currentVersion.version)
        assertEquals(minVersion, chainValue2a.currentVersion.minVersion)
        assertEquals(maxVersion, chainValue2a.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue2a.identity)
        assertTrue(id1.public.verifyChainValue(chainValue2a.currentVersion))
        assertTrue(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 99))
        assertFalse(id1.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 101))
        assertFalse(id2.public.verifyChainValue(chainValue2a.currentVersion.chainHash, 100))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getVersionedId(99)
        }
        val chainValue3 = id1.getVersionedId(101)
        assertEquals(101, chainValue3.currentVersion.version)
        assertEquals(minVersion, chainValue3.currentVersion.minVersion)
        assertEquals(maxVersion, chainValue3.currentVersion.maxVersion)
        assertEquals(id1.public, chainValue3.identity)
        assertTrue(id1.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
        assertFalse(id2.public.verifyChainValue(chainValue3.currentVersion.chainHash, 101))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getVersionedId(maxVersion + 1)
        }
    }

    @Test
    fun `non-minimum version chain test`() {
        val dummySecureRandom = Random()
        dummySecureRandom.setSeed(100)
        val minVersion = 99
        val maxVersion = 256
        val keyMaterial = "Test".toByteArray()
        val simpleHashChain = SimpleHashChainPrivate.generateChain(
            keyMaterial,
            dummySecureRandom,
            maxChainLength = maxVersion,
            minChainLength = minVersion
        )
        dummySecureRandom.setSeed(100)
        val pebbledHashChain = PebbledHashChain.generateChain(
            keyMaterial,
            dummySecureRandom,
            maxChainLength = maxVersion,
            minChainLength = minVersion
        )
        assertFailsWith<java.lang.IllegalArgumentException> {
            simpleHashChain.getSecureVersion(0)
        }
        assertFailsWith<java.lang.IllegalArgumentException> {
            pebbledHashChain.getSecureVersion(0)
        }
        assertFailsWith<java.lang.IllegalArgumentException> {
            simpleHashChain.getSecureVersion(98)
        }
        assertFailsWith<java.lang.IllegalArgumentException> {
            pebbledHashChain.getSecureVersion(98)
        }
        val chainValue1a = simpleHashChain.getSecureVersion(minVersion)
        val chainValue1b = pebbledHashChain.getSecureVersion(minVersion)
        assertEquals(minVersion, chainValue1a.version)
        assertEquals(minVersion, chainValue1a.minVersion)
        assertEquals(maxVersion, chainValue1a.maxVersion)
        assertEquals(minVersion, chainValue1b.version)
        assertEquals(minVersion, chainValue1b.minVersion)
        assertEquals(maxVersion, chainValue1b.maxVersion)
        assertTrue(simpleHashChain.public.verifyChainValue(chainValue1b))
        assertTrue(pebbledHashChain.public.verifyChainValue(chainValue1a))
        val chainValue2a = simpleHashChain.getSecureVersion(maxVersion - 10)
        val chainValue2b = pebbledHashChain.getSecureVersion(maxVersion - 10)
        assertEquals(maxVersion - 10, chainValue2a.version)
        assertEquals(minVersion, chainValue2a.minVersion)
        assertEquals(maxVersion, chainValue2a.maxVersion)
        assertEquals(maxVersion - 10, chainValue2b.version)
        assertEquals(minVersion, chainValue2b.minVersion)
        assertEquals(maxVersion, chainValue2b.maxVersion)
        assertTrue(simpleHashChain.public.verifyChainValue(chainValue2b))
        assertTrue(pebbledHashChain.public.verifyChainValue(chainValue2a))
        val chainValue3a = simpleHashChain.getSecureVersion(maxVersion - 1)
        val chainValue3b = pebbledHashChain.getSecureVersion(maxVersion - 1)
        assertEquals(maxVersion - 1, chainValue3a.version)
        assertEquals(minVersion, chainValue3a.minVersion)
        assertEquals(maxVersion, chainValue3a.maxVersion)
        assertEquals(maxVersion - 1, chainValue3b.version)
        assertEquals(minVersion, chainValue3b.minVersion)
        assertEquals(maxVersion, chainValue3b.maxVersion)
        assertTrue(simpleHashChain.public.verifyChainValue(chainValue3b))
        assertTrue(pebbledHashChain.public.verifyChainValue(chainValue3a))
        val chainValue4a = simpleHashChain.getSecureVersion(maxVersion)
        val chainValue4b = pebbledHashChain.getSecureVersion(maxVersion)
        assertEquals(maxVersion, chainValue4a.version)
        assertEquals(minVersion, chainValue4a.minVersion)
        assertEquals(maxVersion, chainValue4a.maxVersion)
        assertEquals(maxVersion, chainValue4b.version)
        assertEquals(minVersion, chainValue4b.minVersion)
        assertEquals(maxVersion, chainValue4b.maxVersion)
        assertTrue(simpleHashChain.public.verifyChainValue(chainValue4b))
        assertTrue(pebbledHashChain.public.verifyChainValue(chainValue4a))
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
        assertTrue(deserializedChain.verifyChainValue(id1.chainHash, 100, id1.minVersion, id1.maxVersion))
        assertFalse(deserializedChain.verifyChainValue(id1.chainHash, 99, id1.minVersion, id1.maxVersion))
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
            assertTrue(pebbledHashChain.public.verifyChainValue(originalVersion))
        }
        for (i in 150 until 160 step 3) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
            assertTrue(pebbledHashChain.public.verifyChainValue(originalVersion))
        }
        for (i in 2000 until 2010) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
            assertTrue(pebbledHashChain.public.verifyChainValue(originalVersion))
        }
        for (i in HashChainPublic.MAX_CHAIN_LENGTH - 3..HashChainPublic.MAX_CHAIN_LENGTH) {
            val originalVersion = originalHashChain.getSecureVersion(i)
            val pebbledVersion = pebbledHashChain.getSecureVersion(i)
            assertEquals(originalVersion, pebbledVersion)
            assertTrue(originalHashChain.public.verifyChainValue(pebbledVersion))
            assertTrue(pebbledHashChain.public.verifyChainValue(originalVersion))
        }
    }
}