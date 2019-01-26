package uk.co.nesbit.crypto

import djb.Curve25519
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Curve25519Test {
    @Test
    fun `Generate keys`() {
        val keyPair = generateCurve25519DHKeyPair()
        val keyPair2 = generateCurve25519DHKeyPair()
        assertEquals(Curve25519.KEY_SIZE, keyPair.public.encoded.size)
        assertEquals(Curve25519.KEY_SIZE, keyPair.private.encoded.size)
        val zeroOutput = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(zeroOutput, Curve25519.ORDER, keyPair.public.encoded) // Point multiplied by curve order equal zero point
        assertArrayEquals(Curve25519.ZERO, zeroOutput)
        val secretOutput1 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secretOutput1, keyPair2.private.encoded, keyPair.public.encoded)
        val secretOutput2 = ByteArray(Curve25519.KEY_SIZE)
        Curve25519.curve(secretOutput2, keyPair.private.encoded, keyPair2.public.encoded)
        assertArrayEquals(secretOutput1, secretOutput2) // ECDH makes same secret for both parties
        assertTrue { secretOutput1.any { it != 0x00.toByte() } } // which isn't just zero
    }
}