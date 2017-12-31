package com.nesbit.crypto

import com.nesbit.avro.serialize
import com.nesbit.crypto.sphinx.SphinxIdentityKeyPair
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
        val chainValue1 = id1.getChainValue(0)
        Assert.assertEquals(id1.hashChain.targetHash, chainValue1)
        val chainValue2a = id1.getChainValue(100)
        val chainValue2b = id1.getChainValue(100)
        Assert.assertEquals(chainValue2a, chainValue2b)
        Assert.assertTrue(id1.public.verifyChainValue(chainValue2a.bytes, 100))
        Assert.assertFalse(id1.public.verifyChainValue(chainValue2a.bytes, 99))
        Assert.assertFalse(id1.public.verifyChainValue(chainValue2a.bytes, 101))
        Assert.assertFalse(id2.public.verifyChainValue(chainValue2a.bytes, 100))
        assertFailsWith<IllegalArgumentException> {
            // Check version ratchet
            id1.getChainValue(99)
        }
        val chainValue3 = id1.getChainValue(101)
        Assert.assertTrue(id1.public.verifyChainValue(chainValue3, 101))
        Assert.assertFalse(id2.public.verifyChainValue(chainValue3, 101))
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
        val id1 = chain.getChainValue(100)
        assertTrue(deserializedChain.verifyChainValue(id1, 100))
        assertFalse(deserializedChain.verifyChainValue(id1, 99))
    }
}