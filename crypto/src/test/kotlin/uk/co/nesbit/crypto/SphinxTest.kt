package uk.co.nesbit.crypto

import org.junit.Assert.*
import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import kotlin.experimental.xor

class SphinxTest {
    @Test
    fun `Test ECDH chaining from basics`() {
        val rand = newSecureRandom()
        val node0Keys = SphinxIdentityKeyPair.generateKeyPair(rand)
        val node1Keys = SphinxIdentityKeyPair.generateKeyPair(rand)
        val node2Keys = SphinxIdentityKeyPair.generateKeyPair(rand)

        // At initiator
        val xKeyPair = generateCurve25519DHKeyPair(rand)
        val alpha0 = xKeyPair.public
        val secret0 = Curve25519PublicKey(getSharedDHSecret(xKeyPair, node0Keys.public.diffieHellmanPublicKey))
        val hashes0 = Sphinx.DerivedHashes(node0Keys.id, secret0)
        val blind0 = hashes0.blind

        val alpha1 = Curve25519PublicKey(getSharedDHSecret(blind0, alpha0))
        val secret1a = Curve25519PublicKey(getSharedDHSecret(xKeyPair, node1Keys.public.diffieHellmanPublicKey))
        val secret1 = Curve25519PublicKey(getSharedDHSecret(blind0, secret1a))
        val hashes1 = Sphinx.DerivedHashes(node1Keys.id, secret1)
        val blind1 = hashes1.blind

        val alpha2 = Curve25519PublicKey(getSharedDHSecret(blind1, alpha1))
        val secret2a = Curve25519PublicKey(getSharedDHSecret(xKeyPair, node2Keys.public.diffieHellmanPublicKey))
        val secret2b = Curve25519PublicKey(getSharedDHSecret(blind0, secret2a))
        val secret2 = Curve25519PublicKey(getSharedDHSecret(blind1, secret2b))
        val hashes2 = Sphinx.DerivedHashes(node2Keys.id, secret2)
        val blind2 = hashes2.blind

        // At recipients
        val sharedSecret0 = Curve25519PublicKey(getSharedDHSecret(node0Keys.diffieHellmanKeys, alpha0))
        assertEquals(secret0, sharedSecret0)
        val clientHashes0 = Sphinx.DerivedHashes(node0Keys.id, sharedSecret0)
        val clientBlinded0 = clientHashes0.blind
        assertEquals(blind0, clientBlinded0)
        val clientAlpha1 = Curve25519PublicKey(getSharedDHSecret(clientBlinded0, alpha0))
        assertEquals(alpha1, clientAlpha1)

        val sharedSecret1 = Curve25519PublicKey(getSharedDHSecret(node1Keys.diffieHellmanKeys, clientAlpha1))
        assertEquals(secret1, sharedSecret1)
        val clientHashes1 = Sphinx.DerivedHashes(node1Keys.id, sharedSecret1)
        val clientBlinded1 = clientHashes1.blind
        assertEquals(blind1, clientBlinded1)
        val clientAlpha2 = Curve25519PublicKey(getSharedDHSecret(clientBlinded1, clientAlpha1))
        assertArrayEquals(alpha2.keyBytes, clientAlpha2.keyBytes)

        val sharedSecret2 = Curve25519PublicKey(getSharedDHSecret(node2Keys.diffieHellmanKeys, clientAlpha2))
        assertEquals(secret2, sharedSecret2)
        val clientHashes2 = Sphinx.DerivedHashes(node2Keys.id, sharedSecret2)
        val clientBlinded2 = clientHashes2.blind
        assertEquals(blind2, clientBlinded2)
    }

    @Test
    fun `ECDH chaining from general function`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<SphinxIdentityKeyPair>()
        for (i in 0 until sphinx.maxRouteLength) {
            nodeKeys += SphinxIdentityKeyPair.generateKeyPair(rand)
        }
        val route = nodeKeys.map { it.public }
        val dhSequence = sphinx.createRoute(route)

        for (i in 0 until sphinx.maxRouteLength) {
            val node = nodeKeys[i]
            val entry = dhSequence[i]
            val sharedSecret = Curve25519PublicKey(getSharedDHSecret(node.diffieHellmanKeys, entry.alpha))
            assertEquals(entry.sharedSecret, sharedSecret)
            val clientHashes = Sphinx.DerivedHashes(node.id, sharedSecret)
            val clientBlinded = clientHashes.blind
            assertEquals(entry.hashes.blind, clientBlinded)
        }
    }

    @Test
    fun `Single step message`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = SphinxIdentityKeyPair.generateKeyPair(rand)
        val payload = "1234567890".toByteArray()
        val msg = sphinx.makeMessage(listOf(nodeKeys.public), payload, rand)
        val result = sphinx.processMessage(msg, nodeKeys)
        assertTrue(result.valid)
        assertNull(result.forwardMessage)
        assertEquals(nodeKeys.id, result.nextNode)
        assertArrayEquals(payload, result.finalPayload)
    }

    @Test
    fun `Multi step message`() {
        val n = 2
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<SphinxIdentityKeyPair>()
        for (i in 0 until n) {
            nodeKeys += SphinxIdentityKeyPair.generateKeyPair(rand)
        }
        val payload = "1234567890".toByteArray()
        val route = nodeKeys.map { it.public }
        val initialMsg = sphinx.makeMessage(route, payload, rand)
        val step1 = sphinx.processMessage(initialMsg, nodeKeys[0])
        assertTrue(step1.valid)
        assertNotNull(step1.forwardMessage)
        assertEquals(nodeKeys[1].id, step1.nextNode)
        assertNull(step1.finalPayload)
        val result = sphinx.processMessage(step1.forwardMessage!!, nodeKeys[1])
        assertTrue(result.valid)
        assertNull(result.forwardMessage)
        assertEquals(nodeKeys[1].id, result.nextNode)
        assertArrayEquals(payload, result.finalPayload)

    }

    @Test
    fun `All multi-step messages`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val payload = "1234567890".toByteArray()
        val nodeKeys = mutableListOf<SphinxIdentityKeyPair>()
        for (N in 1..sphinx.maxRouteLength) {
            nodeKeys += SphinxIdentityKeyPair.generateKeyPair(rand)
            val route = nodeKeys.map { it.public }
            val initialMsg = sphinx.makeMessage(route, payload, rand)
            var msg: Sphinx.UnpackedSphinxMessage? = initialMsg
            for (i in 0 until N) {
                for (j in 0 until N) {
                    if (i != j) {
                        val bad = sphinx.processMessage(msg!!, nodeKeys[j])
                        assertFalse(bad.valid)
                        assertNull(bad.forwardMessage)
                        assertNull(bad.finalPayload)
                        assertNull(bad.nextNode)
                        sphinx.resetAlphaCache()
                    }
                }
                val badMessage = msg!!.messageBytes
                for (j in 0 until badMessage.size) {
                    for (k in 0 until 8) {
                        val corruptBit = (1 shl k).toByte()
                        badMessage[j] = badMessage[j] xor corruptBit
                        val corruptMessage = Sphinx.UnpackedSphinxMessage(sphinx.betaLength, badMessage)
                        badMessage[j] = badMessage[j] xor corruptBit
                        val bad = sphinx.processMessage(corruptMessage, nodeKeys[i])
                        assertFalse(bad.valid)
                        assertNull(bad.forwardMessage)
                        assertNull(bad.finalPayload)
                        assertNull(bad.nextNode)
                        sphinx.resetAlphaCache()
                    }
                }
                val output = sphinx.processMessage(msg, nodeKeys[i])
                msg = output.forwardMessage
                if (i == N - 1) {
                    assertTrue(output.valid)
                    assertNull(output.forwardMessage)
                    assertArrayEquals(payload, output.finalPayload)
                    assertEquals(nodeKeys[i].id, output.nextNode)
                } else {
                    assertTrue(output.valid)
                    assertNotNull(output.forwardMessage)
                    assertNull(output.finalPayload)
                    assertEquals(nodeKeys[i + 1].id, output.nextNode)
                }
            }
        }
    }

    @Test
    fun `Padding Checks`() {
        val n = 2
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<SphinxIdentityKeyPair>()
        for (i in 0 until n) {
            nodeKeys += SphinxIdentityKeyPair.generateKeyPair(rand)
        }
        for (i in 0 until 3000) {
            val payload = ByteArray(i) { index -> index.toByte() }
            val route = nodeKeys.map { it.public }
            val initialMsg = sphinx.makeMessage(route, payload, rand)
            assertTrue(initialMsg.payload.size > payload.size)
            assertEquals(0, initialMsg.payload.size.rem(sphinx.payloadRoundingSize))
            val step1 = sphinx.processMessage(initialMsg, nodeKeys[0])
            val result = sphinx.processMessage(step1.forwardMessage!!, nodeKeys[1])
            assertArrayEquals(payload, result.finalPayload)
        }
    }

    @Test
    fun `Sphinx ID serialization`() {
        val id = SphinxIdentityKeyPair.generateKeyPair()
        val publicId = id.public
        val serialized = publicId.serialize()
        val deserialized = SphinxPublicIdentity.deserialize(serialized)
        assertEquals(publicId, deserialized)
        val idRecord = publicId.toGenericRecord()
        val deserialized2 = SphinxPublicIdentity(idRecord)
        assertEquals(publicId, deserialized2)
        val id2 = SphinxIdentityKeyPair.generateKeyPair(publicAddress = "server1.somewhere.com:443")
        val publicId2 = id2.public
        val serialized2 = publicId2.serialize()
        val deserialized3 = SphinxPublicIdentity.deserialize(serialized2)
        assertEquals(publicId2, deserialized3)
        val idRecord2 = publicId2.toGenericRecord()
        val deserialized4 = SphinxPublicIdentity(idRecord2)
        assertEquals(publicId2, deserialized4)
    }

    @Test
    fun `Version ID serialization`() {
        val id = SphinxIdentityKeyPair.generateKeyPair()
        val publicId = id.public
        val version = id.hashChain.getSecureVersion(10)
        val versionedID = VersionedIdentity(publicId, version)
        val serialized = versionedID.serialize()
        val deserialized = VersionedIdentity.deserialize(serialized)
        assertEquals(versionedID, deserialized)
        val genericRecord = versionedID.toGenericRecord()
        val deserialized2 = VersionedIdentity(genericRecord)
        assertEquals(versionedID, deserialized2)
    }
}