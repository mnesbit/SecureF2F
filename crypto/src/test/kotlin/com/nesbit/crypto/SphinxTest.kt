package com.nesbit.crypto

import com.nesbit.crypto.sphinx.Sphinx
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
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
        val (msg1, payload1) = sphinx.processMessage(msg, nodeKeys)
        assertEquals(null, msg1)
        assertArrayEquals(payload, payload1)
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
        val (msg1, payload1) = sphinx.processMessage(initialMsg, nodeKeys[0])
        assertEquals(null, payload1)
        val (msg2, payload2) = sphinx.processMessage(msg1!!, nodeKeys[1])
        assertEquals(null, msg2)
        assertArrayEquals(payload, payload2)
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
                        val (bad1, bad2) = sphinx.processMessage(msg!!, nodeKeys[j])
                        assertNull(bad1)
                        assertNull(bad2)
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
                        val (bad1, bad2) = sphinx.processMessage(corruptMessage, nodeKeys[i])
                        assertNull(bad1)
                        assertNull(bad2)
                        sphinx.resetAlphaCache()
                    }
                }
                val output = sphinx.processMessage(msg, nodeKeys[i])
                msg = output.first
                val payloadOut = output.second
                if (i == N - 1) {
                    assertEquals(null, msg)
                    assertArrayEquals(payload, payloadOut)
                } else {
                    assertEquals(null, payloadOut)
                }
            }
        }
    }
}