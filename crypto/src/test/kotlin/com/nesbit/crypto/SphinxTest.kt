package com.nesbit.crypto

import com.nesbit.crypto.sphinx.Sphinx
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import kotlin.experimental.xor
import kotlin.test.assertNull

class SphinxTest {
    @Test
    fun `Test ECDH chaining from basics`() {
        val rand = newSecureRandom()
        val node0Keys = generateCurve25519DHKeyPair(rand)
        val node1Keys = generateCurve25519DHKeyPair(rand)
        val node2Keys = generateCurve25519DHKeyPair(rand)

        // At initiator
        val xKeyPair = generateCurve25519DHKeyPair(rand)
        val alpha0 = xKeyPair.public
        val secret0 = Curve25519PublicKey(getSharedDHSecret(xKeyPair, node0Keys.public))
        val hashes0 = Sphinx.DerivedHashes(node0Keys.public, secret0)
        val blind0 = hashes0.blind

        val alpha1 = Curve25519PublicKey(getSharedDHSecret(blind0, alpha0))
        val secret1a = Curve25519PublicKey(getSharedDHSecret(xKeyPair, node1Keys.public))
        val secret1 = Curve25519PublicKey(getSharedDHSecret(blind0, secret1a))
        val hashes1 = Sphinx.DerivedHashes(node1Keys.public, secret1)
        val blind1 = hashes1.blind

        val alpha2 = Curve25519PublicKey(getSharedDHSecret(blind1, alpha1))
        val secret2a = Curve25519PublicKey(getSharedDHSecret(xKeyPair, node2Keys.public))
        val secret2b = Curve25519PublicKey(getSharedDHSecret(blind0, secret2a))
        val secret2 = Curve25519PublicKey(getSharedDHSecret(blind1, secret2b))
        val hashes2 = Sphinx.DerivedHashes(node2Keys.public, secret2)
        val blind2 = hashes2.blind

        // At recipients
        val sharedSecret0 = Curve25519PublicKey(getSharedDHSecret(node0Keys, alpha0))
        assertEquals(secret0, sharedSecret0)
        val clientHashes0 = Sphinx.DerivedHashes(node0Keys.public, sharedSecret0)
        val clientBlinded0 = clientHashes0.blind
        assertEquals(blind0, clientBlinded0)
        val clientAlpha1 = Curve25519PublicKey(getSharedDHSecret(clientBlinded0, alpha0))
        assertEquals(alpha1, clientAlpha1)

        val sharedSecret1 = Curve25519PublicKey(getSharedDHSecret(node1Keys, clientAlpha1))
        assertEquals(secret1, sharedSecret1)
        val clientHashes1 = Sphinx.DerivedHashes(node1Keys.public, sharedSecret1)
        val clientBlinded1 = clientHashes1.blind
        assertEquals(blind1, clientBlinded1)
        val clientAlpha2 = Curve25519PublicKey(getSharedDHSecret(clientBlinded1, clientAlpha1))
        assertArrayEquals(alpha2.keyBytes, clientAlpha2.keyBytes)

        val sharedSecret2 = Curve25519PublicKey(getSharedDHSecret(node2Keys, clientAlpha2))
        assertEquals(secret2, sharedSecret2)
        val clientHashes2 = Sphinx.DerivedHashes(node2Keys.public, sharedSecret2)
        val clientBlinded2 = clientHashes2.blind
        assertEquals(blind2, clientBlinded2)
    }

    @Test
    fun `ECDH chaining from general function`() {
        val n = 5
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<KeyPair>()
        for (i in 0 until n) {
            nodeKeys += generateCurve25519DHKeyPair(rand)
        }
        val route = nodeKeys.map { it.public }
        val dhSequence = sphinx.createRoute(route)

        for (i in 0 until n) {
            val node = nodeKeys[i]
            val entry = dhSequence[i]
            val sharedSecret = Curve25519PublicKey(getSharedDHSecret(node, entry.alpha))
            assertEquals(entry.sharedSecret, sharedSecret)
            val clientHashes = Sphinx.DerivedHashes(node.public, sharedSecret)
            val clientBlinded = clientHashes.blind
            assertEquals(entry.hashes.blind, clientBlinded)
        }
    }

    @Test
    fun `Single step message`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = generateCurve25519DHKeyPair(rand)
        println(nodeKeys)
        val payload = "1234567890".toByteArray()
        val msg = sphinx.makeMessage(listOf(nodeKeys.public), payload, rand)
        println(msg)
        val result = sphinx.processMessage(msg, nodeKeys)
        assertTrue(result.valid)
        assertNull(result.forwardMessage)
        assertEquals(nodeKeys.public, result.nextNode)
        assertArrayEquals(payload, result.finalPayload)
    }

    @Test
    fun `Multi step message`() {
        val n = 2
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<KeyPair>()
        for (i in 0 until n) {
            nodeKeys += generateCurve25519DHKeyPair(rand)
        }
        val payload = "1234567890".toByteArray()
        val route = nodeKeys.map { it.public }
        val initialMsg = sphinx.makeMessage(route, payload, rand)
        val step1 = sphinx.processMessage(initialMsg, nodeKeys[0])
        assertTrue(step1.valid)
        assertNotNull(step1.forwardMessage)
        assertEquals(nodeKeys[1].public, step1.nextNode)
        assertNull(step1.finalPayload)
        val result = sphinx.processMessage(step1.forwardMessage!!, nodeKeys[1])
        assertTrue(result.valid)
        assertNull(result.forwardMessage)
        assertEquals(nodeKeys[1].public, result.nextNode)
        assertArrayEquals(payload, result.finalPayload)

    }

    @Test
    fun `All multi-step messages`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val payload = "1234567890".toByteArray()
        for (N in 1 until sphinx.maxRouteLength) {
            val nodeKeys = mutableListOf<KeyPair>()
            for (i in 0 until N) {
                nodeKeys += generateCurve25519DHKeyPair(rand)
            }
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
                    assertEquals(nodeKeys[i].public, output.nextNode)
                } else {
                    assertTrue(output.valid)
                    assertNotNull(output.forwardMessage)
                    assertNull(output.finalPayload)
                    assertEquals(nodeKeys[i + 1].public, output.nextNode)
                }
            }
        }
    }
}