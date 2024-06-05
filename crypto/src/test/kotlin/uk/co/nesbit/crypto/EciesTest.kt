package uk.co.nesbit.crypto

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import javax.crypto.AEADBadTagException
import kotlin.experimental.xor
import kotlin.test.assertFailsWith

class EciesTest {
    @Test
    fun `simple roundtrip with aad`() {
        val random = newSecureRandom()
        val targetKeys = listOf(
            generateNACLDHKeyPair(random),
            generateDHKeyPair(random),
            generateECDHKeyPair(random)
        )
        val badTargetKeys = listOf(
            generateNACLDHKeyPair(random),
            generateDHKeyPair(random),
            generateECDHKeyPair(random)
        )
        for (index in targetKeys.indices) {
            val targetKey = targetKeys[index]
            val badTargetKey = badTargetKeys[index]
            val message = "0123456789".toByteArray(Charsets.UTF_8)
            val aad = "header".toByteArray(Charsets.UTF_8)
            val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.public, random)
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
    }

    @Test
    fun `different each time`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val aad = "header".toByteArray(Charsets.UTF_8)
        val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.public, random)
        val encryptedMessage2 = Ecies.encryptMessage(message, aad, targetKey.public, random)
        assertFalse(encryptedMessage.contentEquals(encryptedMessage2))
        val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
        val decryptedMessage2 = Ecies.decryptMessage(encryptedMessage2, aad, targetKey)
        assertArrayEquals(message, decryptedMessage)
        assertArrayEquals(message, decryptedMessage2)
    }

    @Test
    fun `simple roundtrip with no aad`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val encryptedMessage = Ecies.encryptMessage(message, null, targetKey.public, random)
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
        val targetKey = generateNACLDHKeyPair(random)
        val aad = "header".toByteArray(Charsets.UTF_8)

        for (i in 0 until 256) {
            val message = ByteArray(i) { 1 }
            val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.public, random)
            val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
        }
    }

    @Test
    fun `all length aad check`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        for (i in 0 until 256) {
            val aad = ByteArray(i) { 1 }
            val encryptedMessage = Ecies.encryptMessage(message, aad, targetKey.public, random)
            val decryptedMessage = Ecies.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
        }
    }

    @Test
    fun `chacha simple roundtrip with aad`() {
        val random = newSecureRandom()
        val targetKeys = listOf(
            generateNACLDHKeyPair(random),
            generateDHKeyPair(random),
            generateECDHKeyPair(random)
        )
        val badTargetKeys = listOf(
            generateNACLDHKeyPair(random),
            generateDHKeyPair(random),
            generateECDHKeyPair(random)
        )
        for (index in targetKeys.indices) {
            val targetKey = targetKeys[index]
            val badTargetKey = badTargetKeys[index]
            val message = "0123456789".toByteArray(Charsets.UTF_8)
            val aad = "header".toByteArray(Charsets.UTF_8)
            val encryptedMessage = EciesChaCha.encryptMessage(message, aad, targetKey.public, random)
            val decryptedMessage = EciesChaCha.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
            assertFailsWith<AEADBadTagException> {
                EciesChaCha.decryptMessage(encryptedMessage, aad, badTargetKey)
            }
            for (i in aad.indices) {
                aad[0] = aad[0] xor 0x01
                assertFailsWith<AEADBadTagException> {
                    EciesChaCha.decryptMessage(encryptedMessage, aad, targetKey)
                }
                aad[0] = aad[0] xor 0x01
            }
            for (i in encryptedMessage.indices) {
                encryptedMessage[i] = encryptedMessage[i] xor 0x01
                assertFailsWith<AEADBadTagException> {
                    EciesChaCha.decryptMessage(encryptedMessage, aad, targetKey)
                }
                encryptedMessage[i] = encryptedMessage[i] xor 0x01
            }
        }
    }

    @Test
    fun `chacha different each time`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val aad = "header".toByteArray(Charsets.UTF_8)
        val encryptedMessage = EciesChaCha.encryptMessage(message, aad, targetKey.public, random)
        val encryptedMessage2 = EciesChaCha.encryptMessage(message, aad, targetKey.public, random)
        assertFalse(encryptedMessage.contentEquals(encryptedMessage2))
        val decryptedMessage = EciesChaCha.decryptMessage(encryptedMessage, aad, targetKey)
        val decryptedMessage2 = EciesChaCha.decryptMessage(encryptedMessage2, aad, targetKey)
        assertArrayEquals(message, decryptedMessage)
        assertArrayEquals(message, decryptedMessage2)
    }

    @Test
    fun `chacha simple roundtrip with no aad`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val encryptedMessage = EciesChaCha.encryptMessage(message, null, targetKey.public, random)
        val decryptedMessage = EciesChaCha.decryptMessage(encryptedMessage, null, targetKey)
        assertArrayEquals(message, decryptedMessage)
        for (i in encryptedMessage.indices) {
            encryptedMessage[i] = encryptedMessage[i] xor 0x01
            assertFailsWith<AEADBadTagException> {
                EciesChaCha.decryptMessage(encryptedMessage, null, targetKey)
            }
            encryptedMessage[i] = encryptedMessage[i] xor 0x01
        }
    }

    @Test
    fun `chacha all length body check`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val aad = "header".toByteArray(Charsets.UTF_8)

        for (i in 0 until 256) {
            val message = ByteArray(i) { 1 }
            val encryptedMessage = EciesChaCha.encryptMessage(message, aad, targetKey.public, random)
            val decryptedMessage = EciesChaCha.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
        }
    }

    @Test
    fun `chacha all length aad check`() {
        val random = newSecureRandom()
        val targetKey = generateNACLDHKeyPair(random)
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        for (i in 0 until 256) {
            val aad = ByteArray(i) { 1 }
            val encryptedMessage = EciesChaCha.encryptMessage(message, aad, targetKey.public, random)
            val decryptedMessage = EciesChaCha.decryptMessage(encryptedMessage, aad, targetKey)
            assertArrayEquals(message, decryptedMessage)
        }
    }

}