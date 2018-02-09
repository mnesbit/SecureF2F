package uk.co.nesbit.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class UtilsTest {
    @Test
    fun `Test concat function`() {
        val bytes1 = ByteArray(0)
        val bytes2 = "Test".toByteArray()
        val bytes3 = "Things".toByteArray()
        val concat1 = concatByteArrays(bytes1, bytes2)
        assertArrayEquals(bytes2, concat1)
        val concat2 = concatByteArrays(bytes2)
        assertArrayEquals(bytes2, concat2)
        val concat3 = concatByteArrays(bytes2, bytes2)
        assertEquals("TestTest", concat3.toString(Charsets.UTF_8))
        val concat4 = concatByteArrays(bytes2, bytes1, bytes3, bytes2, bytes1)
        assertEquals("TestThingsTest", concat4.toString(Charsets.UTF_8))
    }

    @Test
    fun `Test xor function`() {
        val bytes1 = byteArrayOf(0x00, 0x7F, 0x55, 0xAA.toByte(), 0xFF.toByte(), 0x80.toByte())
        val xor1 = xorByteArrays(bytes1, bytes1)
        assertArrayEquals(ByteArray(bytes1.size), xor1)
        val bytes2 = ByteArray(256, { it.toByte() })
        val bytes3 = bytes2.reversedArray()
        val xor2 = xorByteArrays(bytes2, bytes3)
        xor2.forEachIndexed { index, byte -> assertEquals((index xor (255 - index)).toByte(), byte) }
        val bytes4 = ByteArray(0)
        val xor4 = xorByteArrays(bytes4, bytes4)
        assertArrayEquals(bytes4, xor4)
    }
}