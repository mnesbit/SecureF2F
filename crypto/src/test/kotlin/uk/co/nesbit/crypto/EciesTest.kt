package uk.co.nesbit.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import javax.crypto.AEADBadTagException
import kotlin.experimental.xor
import kotlin.test.assertFailsWith

class EciesTest {
    @Test
    fun `simple roundtrip with aad`() {
        val random = newSecureRandom()
        val targetKey = SphinxIdentityKeyPair.generateKeyPair(random, maxVersion = 64)
        val badTargetKey = SphinxIdentityKeyPair.generateKeyPair(random, maxVersion = 64)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val aad = "header".toByteArray(Charsets.UTF_8)
        val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.diffieHellmanKeys.public, random)
        val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
        assertArrayEquals(message, decryptedMessage)
        assertFailsWith<AEADBadTagException> {
            Ecies.decryptMessage(encryptedMessage, aad, badTargetKey)
        }
        for (i in aad.indices) {
            aad[0] = aad[0] xor 0x01
            assertFailsWith<AEADBadTagException> {
                Ecies.decryptMessage(encryptedMessage, aad, targetKey)
            }
            aad[0] = aad[0] xor 0x01
        }
        for (i in encryptedMessage.indices) {
            encryptedMessage[i] = encryptedMessage[i] xor 0x01
            assertFailsWith<AEADBadTagException> {
                Ecies.decryptMessage(encryptedMessage, aad, targetKey)
            }
            encryptedMessage[i] = encryptedMessage[i] xor 0x01
        }
    }

    @Test
    fun `different each time`() {
        val random = newSecureRandom()
        val targetKey = SphinxIdentityKeyPair.generateKeyPair(random, maxVersion = 64)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val aad = "header".toByteArray(Charsets.UTF_8)
        val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.diffieHellmanKeys.public, random)
        val encryptedMessage2 = Ecies.encryptMessage(message, aad, targetKey.diffieHellmanKeys.public, random)
        assertFalse(encryptedMessage.contentEquals(encryptedMessage2))
        val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
        val decryptedMessage2 = Ecies.decryptMessage(encryptedMessage2, aad, targetKey)
        assertArrayEquals(message, decryptedMessage)
        assertArrayEquals(message, decryptedMessage2)
    }

    @Test
    fun `simple roundtrip with no aad`() {
        val random = newSecureRandom()
        val targetKey = SphinxIdentityKeyPair.generateKeyPair(random, maxVersion = 64)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val encryptedMessage = Ecies.encryptMessage(message, null, targetKey.diffieHellmanKeys.public, random)
        val decryptedMessage = Ecies.decryptMessage(encryptedMessage, null, targetKey)
        assertArrayEquals(message, decryptedMessage)
        for (i in encryptedMessage.indices) {
            encryptedMessage[i] = encryptedMessage[i] xor 0x01
            assertFailsWith<AEADBadTagException> {
                Ecies.decryptMessage(encryptedMessage, null, targetKey)
            }
            encryptedMessage[i] = encryptedMessage[i] xor 0x01
        }
    }

    @Test
    fun `all length body check`() {
        val random = newSecureRandom()
        val targetKey = SphinxIdentityKeyPair.generateKeyPair(random, maxVersion = 64)
        val aad = "header".toByteArray(Charsets.UTF_8)

        for (i in 0 until 256) {
            val message = ByteArray(i) { 1 }
            val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.diffieHellmanKeys.public, random)
            val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
        }
    }

    @Test
    fun `all length aad check`() {
        val random = newSecureRandom()
        val targetKey = SphinxIdentityKeyPair.generateKeyPair(random, maxVersion = 64)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        for (i in 0 until 256) {
            val aad = ByteArray(i) { 1 }
            val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.diffieHellmanKeys.public, random)
            val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
        }
    }

}