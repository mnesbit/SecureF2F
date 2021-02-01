package uk.co.nesbit.crypto

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair

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

    private fun testString(str: String, seed: Int, expected: Int) {
        val hash = MurmurHash3.hash32(str, 0, str.length, seed)
        assertEquals(expected, hash)
    }

    //Test vectors from https://stackoverflow.com/questions/14747343/murmurhash3-test-vectors
    @Test
    fun `Test murmurhash3`() {
        testString("", 0, 0) //empty string with zero seed should give zero
        testString("", 1, 0x514E28B7)
        testString("", 0xffffffffL.toInt(), 0x81F16F39L.toInt()) //make sure seed value is handled unsigned
        testString("\u0000".repeat(4), 0, 0x2362F9DE) //make sure we handle embedded nulls


        testString("aaaa", 0x9747b28cL.toInt(), 0x5A97808A) //one full chunk
        testString("aaa", 0x9747b28cL.toInt(), 0x283E0130) //three characters
        testString("aa", 0x9747b28cL.toInt(), 0x5D211726) //two characters
        testString("a", 0x9747b28cL.toInt(), 0x7FA09EA6) //one character

        //Endian order within the chunks
        testString("abcd", 0x9747b28cL.toInt(), 0xF0478627L.toInt()) //one full chunk
        testString("abc", 0x9747b28cL.toInt(), 0xC84A62DDL.toInt())
        testString("ab", 0x9747b28cL.toInt(), 0x74875592)
        testString("a", 0x9747b28cL.toInt(), 0x7FA09EA6)

        testString("Hello, world!", 0x9747b28cL.toInt(), 0x24884CBA)

        //Make sure you handle UTF-8 high characters. A bcrypt implementation messed this up
        testString("ππππππππ", 0x9747b28cL.toInt(), 0xD58063C1L.toInt()) //U+03C0: Greek Small Letter Pi

        //String of 256 characters.
        //Make sure you don't store string lengths in a char, and overflow at 255 bytes (as OpenBSD's canonical BCrypt implementation did)
        testString("a".repeat(256), 0x9747b28cL.toInt(), 0x37405BDC)
    }

    @Test
    fun `BloomFilter test`() {
        val filter = BloomFilter(100, 0.02, 99)
        for (i in 0 until 100) {
            filter.add(i.toByteArray())
        }
        for (i in 0 until 100) {
            assertEquals(true, filter.possiblyContains(i.toByteArray()))
        }
        var count = 0
        for (i in 101 until 200) {
            if (filter.possiblyContains(i.toByteArray())) {
                ++count
            }
        }
        assertTrue(count.toDouble() < 2.0 * filter.expectedItemCount * filter.falsePositiveRate)
        assertEquals(false, filter.possiblyContains(200.toByteArray()))
        assertEquals(false, filter.possiblyContains(500.toByteArray()))
        assertEquals(false, filter.possiblyContains(1000.toByteArray()))
        assertEquals(false, filter.possiblyContains(2000.toByteArray()))
        val bytes = filter.serialize()
        val deserialized = BloomFilter.deserialize(bytes)
        assertEquals(filter, deserialized)
        deserialized.add(500.toByteArray())
        assertEquals(true, deserialized.possiblyContains(500.toByteArray()))
        assertNotEquals(filter, deserialized)
    }

    @Test
    fun `SignedData test`() {
        val keys = SphinxIdentityKeyPair.generateKeyPair()
        val value1 = "0123456789".toByteArray(Charsets.UTF_8)
        val data1 = SignedData(value1, keys.signingKeys.sign(value1).toDigitalSignature())
        data1.verify(keys.signingKeys.public)
        val data1Bytes = data1.serialize()
        val data1Deserialized = SignedData.deserialize(data1Bytes)
        assertEquals(data1, data1Deserialized)
        data1Deserialized.verify(keys.signingKeys.public)
        val value2 = keys.public
        val data2 = SignedData.createSignedData(value2) { keys.signingKeys.sign(it).toDigitalSignature() }
        data2.verify(keys.signingKeys.public)
        val data2Bytes = data2.serialize()
        val data2Deserialized = SignedData.deserialize(data2Bytes)
        assertEquals(data2, data2Deserialized)
        data2Deserialized.verify(keys.signingKeys.public)
    }
}