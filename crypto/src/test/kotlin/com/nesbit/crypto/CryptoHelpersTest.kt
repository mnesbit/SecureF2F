package com.nesbit.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import java.security.SignatureException
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals


class CryptoHelpersTest {
    @Test
    fun `test EdDSA verify`() {
        val keyPair = generateEdDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
    }

    @Test
    fun `test ECDSA verify`() {
        val keyPair = generateECDSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
    }

    @Test
    fun `test RSA verify`() {
        val keyPair = generateRSAKeyPair()
        val bytes = "jhsdjsjfajkf".toByteArray()
        val signature = keyPair.sign(bytes)
        signature.verify(bytes)

        bytes[0] = 'k'.toByte()

        assertFailsWith<SignatureException> {
            signature.verify(bytes)
        }
    }

    @Test
    fun `Test Diffie Hellman helpers`() {
        val key1 = generateDHKeyPair()
        val key2 = generateDHKeyPair()
        val sec1 = getSharedDHSecret(key1, key2.public)
        val sec2 = getSharedDHSecret(key2, key1.public)
        assertArrayEquals(sec1, sec2)

        val key3 = generateECDHKeyPair()
        val key4 = generateECDHKeyPair()
        val sec3 = getSharedDHSecret(key3, key4.public)
        val sec4 = getSharedDHSecret(key4, key3.public)
        assertArrayEquals(sec3, sec4)

        val key5 = generateCurve25519DHKeyPair()
        val key6 = generateCurve25519DHKeyPair()
        val sec5 = getSharedDHSecret(key5, key6.public)
        val sec6 = getSharedDHSecret(key6, key5.public)
        assertArrayEquals(sec5, sec6)

        val bytes = "jhASDJHKSD".toByteArray(Charsets.UTF_8)
        val hash1 = getHMAC(sec1, bytes)
        val hash2 = getHMAC(sec2, bytes)
        val hash3 = getHMAC(sec3, bytes)
        val hash4 = getHMAC(sec1, "jhASDJHKSE".toByteArray(Charsets.UTF_8))
        assertEquals(hash1, hash2)
        assertNotEquals(hash1, hash3)
        assertNotEquals(hash1, hash4)

        assertFails {
            getSharedDHSecret(key1, key3.public)
        }

        assertFails {
            getSharedDHSecret(key3, key1.public)
        }

        assertFails {
            getSharedDHSecret(key1, key5.public)
        }

        assertFails {
            getSharedDHSecret(key3, key5.public)
        }
    }

    @Test
    fun `Test signatures with hashes and bytes are interchangeable`() {
        val bytes = "112543153513456".toByteArray(Charsets.UTF_8)
        val bytes2 = "112543153513457".toByteArray(Charsets.UTF_8)

        val keyRSA = generateRSAKeyPair()
        val sig1 = keyRSA.sign(SecureHash.secureHash(bytes))
        sig1.verify(bytes)
        assertFails {
            sig1.verify(bytes2)
        }

        val keyECDSA = generateECDSAKeyPair()
        val sig2 = keyECDSA.sign(SecureHash.secureHash(bytes))
        sig2.verify(bytes)
        assertFails {
            sig2.verify(bytes2)
        }

        val sig3 = keyRSA.sign(bytes)
        sig3.verify(SecureHash.secureHash(bytes))
        assertFails {
            sig3.verify(SecureHash.secureHash(bytes2))
        }

        val sig4 = keyECDSA.sign(bytes)
        sig4.verify(SecureHash.secureHash(bytes))
        assertFails {
            sig4.verify(SecureHash.secureHash(bytes2))
        }

    }
}