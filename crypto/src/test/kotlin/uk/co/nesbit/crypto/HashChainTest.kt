package uk.co.nesbit.crypto

import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import org.junit.Assert
import org.junit.Test
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
        val chain = HashChainPrivate.generateChain("Test".toByteArray())
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
}