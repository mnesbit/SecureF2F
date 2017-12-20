package com.nesbit.crypto

import com.nesbit.crypto.sphinx.Sphinx
import djb.Curve25519
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class SphinxTest {
    @Test
    fun `Test Rho stream`() {
        val rand = newSecureRandom()
        val key1 = ByteArray(256 / 8)
        rand.nextBytes(key1)
        val rho = Sphinx.rho(key1, 100)
        println(rho.printHex())
    }

    @Test
    fun `Test ECDH chaining`() {
        val rand = newSecureRandom()
        val node0Key = Curve25519KeyPair.generateKeyPair(rand)
        val node1Key = Curve25519KeyPair.generateKeyPair(rand)
        val node2Key = Curve25519KeyPair.generateKeyPair(rand)

        // At initiator
        val xKeyPair = Curve25519KeyPair.generateKeyPair(rand)
        val alpha0 = xKeyPair.publicKey
        val secret0 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secret0, xKeyPair.privateKey.keyBytes, node0Key.publicKey.keyBytes)
        val hashes0 = Sphinx.DerivedHashes(node0Key.publicKey, secret0)
        val blind0 = hashes0.blind

        val alpha1 = Curve25519PublicKey(ByteArray(Curve25519.KEY_SIZE))
        Curve25519.curve(alpha1.keyBytes, blind0, alpha0.keyBytes)
        val secret1a = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secret1a, xKeyPair.privateKey.keyBytes, node1Key.publicKey.keyBytes)
        val secret1 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secret1, blind0, secret1a)
        val hashes1 = Sphinx.DerivedHashes(node1Key.publicKey, secret1)
        val blind1 = hashes1.blind

        val alpha2 = Curve25519PublicKey(ByteArray(Curve25519.KEY_SIZE))
        Curve25519.curve(alpha2.keyBytes, blind1, alpha1.keyBytes)
        val secret2a = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secret2a, xKeyPair.privateKey.keyBytes, node2Key.publicKey.keyBytes)
        val secret2b = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secret2b, blind0, secret2a)
        val secret2 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secret2, blind1, secret2b)
        val hashes2 = Sphinx.DerivedHashes(node2Key.publicKey, secret2)
        val blind2 = hashes2.blind

        // At recipients
        val sharedSecret0 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(sharedSecret0, node0Key.privateKey.keyBytes, alpha0.keyBytes)
        assertArrayEquals(secret0, sharedSecret0)
        val clientHashes0 = Sphinx.DerivedHashes(node0Key.publicKey, sharedSecret0)
        val clientBlinded0 = clientHashes0.blind
        assertArrayEquals(blind0, clientBlinded0)
        val clientAlpha1 = Curve25519PublicKey(ByteArray(Curve25519.KEY_SIZE))
        Curve25519.curve(clientAlpha1.keyBytes, clientBlinded0, alpha0.keyBytes)
        assertArrayEquals(alpha1.keyBytes, clientAlpha1.keyBytes)

        val sharedSecret1 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(sharedSecret1, node1Key.privateKey.keyBytes, clientAlpha1.keyBytes)
        assertArrayEquals(secret1, sharedSecret1)
        val clientHashes1 = Sphinx.DerivedHashes(node1Key.publicKey, sharedSecret1)
        val clientBlinded1 = clientHashes1.blind
        assertArrayEquals(blind1, clientBlinded1)
        val clientAlpha2 = Curve25519PublicKey(ByteArray(Curve25519.KEY_SIZE))
        Curve25519.curve(clientAlpha2.keyBytes, clientBlinded1, clientAlpha1.keyBytes)
        assertArrayEquals(alpha2.keyBytes, clientAlpha2.keyBytes)

        val sharedSecret2 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(sharedSecret2, node2Key.privateKey.keyBytes, clientAlpha2.keyBytes)
        assertArrayEquals(secret2, sharedSecret2)
        val clientHashes2 = Sphinx.DerivedHashes(node2Key.publicKey, sharedSecret2)
        val clientBlinded2 = clientHashes2.blind
        assertArrayEquals(blind2, clientBlinded2)
    }
}