package uk.co.nesbit.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.ratchet.RatchetException
import uk.co.nesbit.crypto.ratchet.RatchetHeader
import uk.co.nesbit.crypto.ratchet.RatchetMessage
import uk.co.nesbit.crypto.ratchet.RatchetState
import kotlin.experimental.xor
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RatchetTest {
    @Test
    fun `Serialisation of RatchetHeader`() {
        val dhKeyPair = generateCurve25519DHKeyPair()
        val ratchetHeader = RatchetHeader(dhKeyPair.public, 1, 2)
        val serialized = ratchetHeader.serialize()
        val ratchetHeaderDeserialized = RatchetHeader.deserialize(serialized)
        assertEquals(ratchetHeader, ratchetHeaderDeserialized)
        val headerRecord = ratchetHeader.toGenericRecord()
        val ratchetHeaderDeserialized2 = RatchetHeader(headerRecord)
        assertEquals(ratchetHeader, ratchetHeaderDeserialized2)
    }

    @Test
    fun `Serialisation of RatchetMessage`() {
        val ratchetMessage = RatchetMessage("header".toByteArray(Charsets.UTF_8), "message".toByteArray(Charsets.UTF_8))
        val serialized = ratchetMessage.serialize()
        val ratchetMessageDeserialized = RatchetMessage.deserialize(serialized)
        assertEquals(ratchetMessage, ratchetMessageDeserialized)
        val headerRecord = ratchetMessage.toGenericRecord()
        val ratchetMessageDeserialized2 = RatchetMessage(headerRecord)
        assertEquals(ratchetMessage, ratchetMessageDeserialized2)
    }

    @Test
    fun `Single message exchange`() {
        val secureRandom = newSecureRandom()
        val bobInitialIdentity = generateCurve25519DHKeyPair(secureRandom)
        val sessionStartingSecret = "secret words".toByteArray(Charsets.UTF_8)
        val ratchetAlice = RatchetState.ratchetInitAlice(sessionStartingSecret, bobInitialIdentity.public, secureRandom)
        val ratchetBob = RatchetState.ratchetInitBob(sessionStartingSecret, bobInitialIdentity, secureRandom)
        val alicePlaintext = "From Alice".toByteArray(Charsets.UTF_8)
        val aliceFirstMessage = ratchetAlice.encryptMessage(alicePlaintext, null)
        val decryptedMessage1 = ratchetBob.decryptMessage(aliceFirstMessage, null)
        assertArrayEquals(alicePlaintext, decryptedMessage1)
        val bobPlaintext = "From Bob".toByteArray(Charsets.UTF_8)
        val bobFirstMessage = ratchetBob.encryptMessage(bobPlaintext, null)
        val decryptedMessage2 = ratchetAlice.decryptMessage(bobFirstMessage, null)
        assertArrayEquals(bobPlaintext, decryptedMessage2)
    }

    @Test
    fun `Messages with different strides`() {
        val secureRandom = newSecureRandom()
        val bobInitialIdentity = generateCurve25519DHKeyPair(secureRandom)
        val sessionStartingSecret = "secret words".toByteArray(Charsets.UTF_8)
        val ratchetAlice = RatchetState.ratchetInitAlice(sessionStartingSecret, bobInitialIdentity.public, secureRandom)
        val ratchetBob = RatchetState.ratchetInitBob(sessionStartingSecret, bobInitialIdentity, secureRandom)
        var msgCount = 0
        for (i in 0 until 100) {
            val aliceSends = 1 + secureRandom.nextInt(10)
            for (j in 0 until aliceSends) {
                val msg = "from alice $msgCount".toByteArray(Charsets.UTF_8)
                val aad = ByteArray(1) { msgCount.toByte() }
                ++msgCount
                val aliceMessage = ratchetAlice.encryptMessage(msg, aad)
                val bobDecode = ratchetBob.decryptMessage(aliceMessage, aad)
                assertArrayEquals(msg, bobDecode)
            }
            val bobSends = 1 + secureRandom.nextInt(10)
            for (j in 0 until bobSends) {
                val msg = "from bob $msgCount".toByteArray(Charsets.UTF_8)
                val aad = ByteArray(1) { msgCount.toByte() }
                ++msgCount
                val bobMessage = ratchetBob.encryptMessage(msg, aad)
                val aliceDecode = ratchetAlice.decryptMessage(bobMessage, aad)
                assertArrayEquals(msg, aliceDecode)
            }
        }
    }


    @Test
    fun `Corrupted messages are caught`() {
        val secureRandom = newSecureRandom()
        val bobInitialIdentity = generateCurve25519DHKeyPair(secureRandom)
        val sessionStartingSecret = "secret words".toByteArray(Charsets.UTF_8)
        val ratchetAlice = RatchetState.ratchetInitAlice(sessionStartingSecret, bobInitialIdentity.public, secureRandom)
        val ratchetBob = RatchetState.ratchetInitBob(sessionStartingSecret, bobInitialIdentity, secureRandom)
        val alicePlaintext = "From Alice".toByteArray(Charsets.UTF_8)
        val aliceMessage = ratchetAlice.encryptMessage(alicePlaintext, null)
        for (i in 0 until aliceMessage.size) {
            for (j in 0 until 8) {
                val mask = (1 shl j).toByte()
                aliceMessage[i] = aliceMessage[i] xor mask
                assertFailsWith<RatchetException> {
                    ratchetBob.decryptMessage(aliceMessage, null)
                }
                aliceMessage[i] = aliceMessage[i] xor mask
            }
        }
        val decryptedMessage1 = ratchetBob.decryptMessage(aliceMessage, null) // have to prime bob
        assertArrayEquals(alicePlaintext, decryptedMessage1)
        val bobPlaintext = "From Bob".toByteArray(Charsets.UTF_8)
        val bobMessage = ratchetBob.encryptMessage(bobPlaintext, null)
        for (i in 0 until bobMessage.size) {
            for (j in 0 until 8) {
                val mask = (1 shl j).toByte()
                bobMessage[i] = bobMessage[i] xor mask
                assertFailsWith<RatchetException> {
                    ratchetAlice.decryptMessage(bobMessage, null)
                }
                bobMessage[i] = bobMessage[i] xor mask
            }
        }
        val decryptedMessage2 = ratchetAlice.decryptMessage(bobMessage, null) // have to prime bob
        assertArrayEquals(bobPlaintext, decryptedMessage2)
    }

    @Test
    fun `Drop initial messages`() {
        val secureRandom = newSecureRandom()
        val bobInitialIdentity = generateCurve25519DHKeyPair(secureRandom)
        val sessionStartingSecret = "secret words".toByteArray(Charsets.UTF_8)
        val ratchetAlice = RatchetState.ratchetInitAlice(sessionStartingSecret, bobInitialIdentity.public, secureRandom)
        val ratchetBob = RatchetState.ratchetInitBob(sessionStartingSecret, bobInitialIdentity, secureRandom)
        val alicePlaintext = "From Alice".toByteArray(Charsets.UTF_8)
        val alicePlaintext2 = "From Alice2".toByteArray(Charsets.UTF_8)
        ratchetAlice.encryptMessage(alicePlaintext, null) //drop one message
        val aliceSecondMessage = ratchetAlice.encryptMessage(alicePlaintext2, null)
        val decryptedMessage1 = ratchetBob.decryptMessage(aliceSecondMessage, null)
        assertArrayEquals(alicePlaintext2, decryptedMessage1)
        val bobPlaintext = "From Bob".toByteArray(Charsets.UTF_8)
        val bobPlaintext2 = "From Bob2".toByteArray(Charsets.UTF_8)
        ratchetBob.encryptMessage(bobPlaintext, null) // drop one message
        val bobSecondMessage = ratchetBob.encryptMessage(bobPlaintext2, null)
        val decryptedMessage2 = ratchetAlice.decryptMessage(bobSecondMessage, null)
        assertArrayEquals(bobPlaintext2, decryptedMessage2)
    }

    @Test
    fun `Scrambled ordering`() {
        val secureRandom = newSecureRandom()
        val bobInitialIdentity = generateCurve25519DHKeyPair(secureRandom)
        val sessionStartingSecret = "secret words".toByteArray(Charsets.UTF_8)
        val ratchetAlice = RatchetState.ratchetInitAlice(sessionStartingSecret, bobInitialIdentity.public, secureRandom, 5)
        val ratchetBob = RatchetState.ratchetInitBob(sessionStartingSecret, bobInitialIdentity, secureRandom)
        var msgCount = 0
        for (i in 0 until 10) {
            val aliceMessages = mutableListOf<Pair<ByteArray, ByteArray>>()
            for (j in 0 until ratchetBob.maxSkip) {
                val msg = "from alice $msgCount".toByteArray(Charsets.UTF_8)
                ++msgCount
                aliceMessages += Pair(msg, ratchetAlice.encryptMessage(msg, null))
            }
            for (j in 0 until ratchetBob.maxSkip) {
                val (msg, aliceMessage) = aliceMessages[ratchetBob.maxSkip - j - 1]
                val bobDecode = ratchetBob.decryptMessage(aliceMessage, null)
                assertArrayEquals(msg, bobDecode)
            }
            val bobMessages = mutableListOf<Pair<ByteArray, ByteArray>>()
            for (j in 0 until ratchetAlice.maxSkip) {
                val msg = "from bob $msgCount".toByteArray(Charsets.UTF_8)
                ++msgCount
                bobMessages += Pair(msg, ratchetBob.encryptMessage(msg, null))
            }
            for (j in 0 until ratchetAlice.maxSkip) {
                val (msg, bobMessage) = bobMessages[ratchetAlice.maxSkip - j - 1]
                val aliceDecode = ratchetAlice.decryptMessage(bobMessage, null)
                assertArrayEquals(msg, aliceDecode)
            }
        }
    }

}