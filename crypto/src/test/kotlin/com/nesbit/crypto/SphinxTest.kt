package com.nesbit.crypto

import com.nesbit.crypto.sphinx.Sphinx
import org.junit.Assert.*
import org.junit.Test
import kotlin.experimental.xor
import kotlin.test.assertNull

class SphinxTest {
    @Test
    fun `Test ECDH chaining from basics`() {
        val rand = newSecureRandom()
        val node0Keys = Curve25519KeyPair.generateKeyPair(rand)
        val node1Keys = Curve25519KeyPair.generateKeyPair(rand)
        val node2Keys = Curve25519KeyPair.generateKeyPair(rand)

        // At initiator
        val xKeyPair = Curve25519KeyPair.generateKeyPair(rand)
        val alpha0 = xKeyPair.publicKey
        val secret0 = generateSharedECDHSecret(node0Keys.publicKey, xKeyPair.privateKey)
        val hashes0 = Sphinx.DerivedHashes(node0Keys.publicKey, secret0)
        val blind0 = hashes0.blind

        val alpha1 = generateSharedECDHSecret(alpha0, blind0)
        val secret1a = generateSharedECDHSecret(node1Keys.publicKey, xKeyPair.privateKey)
        val secret1 = generateSharedECDHSecret(secret1a, blind0)
        val hashes1 = Sphinx.DerivedHashes(node1Keys.publicKey, secret1)
        val blind1 = hashes1.blind

        val alpha2 = generateSharedECDHSecret(alpha1, blind1)
        val secret2a = generateSharedECDHSecret(node2Keys.publicKey, xKeyPair.privateKey)
        val secret2b = generateSharedECDHSecret(secret2a, blind0)
        val secret2 = generateSharedECDHSecret(secret2b, blind1)
        val hashes2 = Sphinx.DerivedHashes(node2Keys.publicKey, secret2)
        val blind2 = hashes2.blind

        // At recipients
        val sharedSecret0 = generateSharedECDHSecret(alpha0, node0Keys.privateKey)
        assertEquals(secret0, sharedSecret0)
        val clientHashes0 = Sphinx.DerivedHashes(node0Keys.publicKey, sharedSecret0)
        val clientBlinded0 = clientHashes0.blind
        assertEquals(blind0, clientBlinded0)
        val clientAlpha1 = generateSharedECDHSecret(alpha0, clientBlinded0)
        assertEquals(alpha1, clientAlpha1)

        val sharedSecret1 = generateSharedECDHSecret(clientAlpha1, node1Keys.privateKey)
        assertEquals(secret1, sharedSecret1)
        val clientHashes1 = Sphinx.DerivedHashes(node1Keys.publicKey, sharedSecret1)
        val clientBlinded1 = clientHashes1.blind
        assertEquals(blind1, clientBlinded1)
        val clientAlpha2 = generateSharedECDHSecret(clientAlpha1, clientBlinded1)
        assertArrayEquals(alpha2.keyBytes, clientAlpha2.keyBytes)

        val sharedSecret2 = generateSharedECDHSecret(clientAlpha2, node2Keys.privateKey)
        assertEquals(secret2, sharedSecret2)
        val clientHashes2 = Sphinx.DerivedHashes(node2Keys.publicKey, sharedSecret2)
        val clientBlinded2 = clientHashes2.blind
        assertEquals(blind2, clientBlinded2)
    }

    @Test
    fun `ECDH chaining from general function`() {
        val n = 5
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<Curve25519KeyPair>()
        for (i in 0 until n) {
            nodeKeys += Curve25519KeyPair.generateKeyPair(rand)
        }
        val route = nodeKeys.map { it.publicKey }
        val dhSequence = sphinx.createRoute(route)

        for (i in 0 until n) {
            val node = nodeKeys[i]
            val entry = dhSequence[i]
            val sharedSecret = generateSharedECDHSecret(entry.alpha, node.privateKey)
            assertEquals(entry.sharedSecret, sharedSecret)
            val clientHashes = Sphinx.DerivedHashes(node.publicKey, sharedSecret)
            val clientBlinded = clientHashes.blind
            assertEquals(entry.hashes.blind, clientBlinded)
        }
    }

    @Test
    fun `Single step message`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = Curve25519KeyPair.generateKeyPair(rand)
        println(nodeKeys)
        val payload = "1234567890".toByteArray()
        val msg = sphinx.makeMessage(listOf(nodeKeys.publicKey), payload, rand)
        println(msg)
        val result = sphinx.processMessage(msg, nodeKeys)
        assertTrue(result.valid)
        assertNull(result.forwardMessage)
        assertEquals(nodeKeys.publicKey, result.nextNode)
        assertArrayEquals(payload, result.finalPayload)
    }

    @Test
    fun `Multi step message`() {
        val n = 2
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val nodeKeys = mutableListOf<Curve25519KeyPair>()
        for (i in 0 until n) {
            nodeKeys += Curve25519KeyPair.generateKeyPair(rand)
        }
        val payload = "1234567890".toByteArray()
        val route = nodeKeys.map { it.publicKey }
        val initialMsg = sphinx.makeMessage(route, payload, rand)
        val step1 = sphinx.processMessage(initialMsg, nodeKeys[0])
        assertTrue(step1.valid)
        assertNotNull(step1.forwardMessage)
        assertEquals(nodeKeys[1].publicKey, step1.nextNode)
        assertNull(step1.finalPayload)
        val result = sphinx.processMessage(step1.forwardMessage!!, nodeKeys[1])
        assertTrue(result.valid)
        assertNull(result.forwardMessage)
        assertEquals(nodeKeys[1].publicKey, result.nextNode)
        assertArrayEquals(payload, result.finalPayload)

    }

    @Test
    fun `Multi step message 3`() {
        val rand = newSecureRandom()
        val sphinx = Sphinx(rand)
        val payload = "1234567890".toByteArray()
        for (N in 1 until sphinx.maxRouteLength) {
            val nodeKeys = mutableListOf<Curve25519KeyPair>()
            for (i in 0 until N) {
                nodeKeys += Curve25519KeyPair.generateKeyPair(rand)
            }
            val route = nodeKeys.map { it.publicKey }
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
                    assertEquals(nodeKeys[i].publicKey, output.nextNode)
                } else {
                    assertTrue(output.valid)
                    assertNotNull(output.forwardMessage)
                    assertNull(output.finalPayload)
                    assertEquals(nodeKeys[i + 1].publicKey, output.nextNode)
                }
            }
        }
    }
}