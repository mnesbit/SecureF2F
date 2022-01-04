package uk.co.nesbit.crypto

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.setsync.InvertibleBloomFilter
import uk.co.nesbit.crypto.setsync.SizeEstimator
import java.util.*

class SetSyncTest {
    @Test
    fun `basic serialisation test`() {
        val filter = InvertibleBloomFilter(100, 400)
        val values = (1 until 100).toSet()
        for (value in values) {
            filter.add(value)
        }
        val serialised = filter.serialize()
        val deserialized = InvertibleBloomFilter.deserialize(serialised)
        assertEquals(filter, deserialized)
        val decode = filter.decode()
        assertEquals(true, decode.ok)
        assertEquals(true, decode.deleted.isEmpty())
        assertEquals(values, decode.added)
    }

    @Test
    fun `Basic function test`() {
        val filter1 = InvertibleBloomFilter(100, 400)
        val values1 = (0 until 100).toSet()
        for (value in values1) {
            filter1.add(value)
        }
        val values2 = (50 until 150).toSet()
        val decoded = filter1.decode(values2)
        assertEquals(true, decoded.ok)
        assertEquals(values1.minus(values2), decoded.added)
        assertEquals(values2.minus(values1), decoded.deleted)
    }

    @Test
    fun `threshold test`() {
        val values1 = (0 until 100).toSet()
        val values2 = (50 until 150).toSet()
        val rand = Random()
        var decodedOK = 0
        var decodedBAD = 0
        for (size in 1 until 400) {
            val filter1 = InvertibleBloomFilter(rand.nextInt(), size)
            for (value in values1) {
                filter1.add(value)
            }
            val decoded = filter1.decode(values2)
            if (decoded.ok) {
                assertEquals(values1.minus(values2), decoded.added)
                assertEquals(values2.minus(values1), decoded.deleted)
                ++decodedOK
            } else {
                ++decodedBAD
            }
        }
        assertEquals(true, decodedBAD > 0)
        assertEquals(true, decodedBAD < 300)
        assertEquals(true, decodedOK > 50)
    }

    @Test
    fun `threshold test2`() {
        var decodedOK = 0
        var decodedBAD = 0
        val random = Random()
        for (size in 0 until 500) {
            val values1 = (0 until 8000).toSet()
            val values2 = (size until (8000 + size)).toSet()
            val filter1 = InvertibleBloomFilter(random.nextInt(), 200)
            for (value in values1) {
                filter1.add(value)
            }
            val decoded = filter1.decode(values2)
            if (decoded.ok) {
                assertEquals(values1.minus(values2), decoded.added)
                assertEquals(values2.minus(values1), decoded.deleted)
                ++decodedOK
            } else {
                ++decodedBAD
            }
        }
        assertEquals(true, decodedBAD > 0)
        assertEquals(true, decodedBAD < 450)
        assertEquals(true, decodedOK > 15)
    }

    @Test
    fun `test size independence`() {
        var decodedOK = 0
        var decodedBAD = 0
        val random = Random()
        for (scale in 1..10) {
            val size = 1000 shl scale
            val values1 = (0 until size).toSet()
            val values2 = (50 until (50 + size)).toSet()
            val filter1 = InvertibleBloomFilter(random.nextInt(), 400)
            for (value in values1) {
                filter1.add(value)
            }
            val decoded = filter1.decode(values2)
            if (decoded.ok) {
                assertEquals(values1.minus(values2), decoded.added)
                assertEquals(values2.minus(values1), decoded.deleted)
                ++decodedOK
            } else {
                ++decodedBAD
            }
        }
        assertEquals(0, decodedBAD)
        assertEquals(10, decodedOK)
    }

    @Test
    fun `estimator test`() {
        var decodeOK = 0
        var decodeBAD = 0
        for (i in 1 until 1000) {
            val values1 = (0 until 10000).toSet()
            val values2 = (i until (10000 + i)).toSet()
            val estimator = SizeEstimator.createSizeEstimatorRequest(values1)
            val response = estimator.calculateResponse(values2)
            val decode = response.decode(values1)
            if (decode.ok) {
                ++decodeOK
                assertEquals(values1.minus(values2), decode.deleted)
                assertEquals(values2.minus(values1), decode.added)
            } else {
                ++decodeBAD
            }
        }
        assertEquals(true, decodeOK > 970)
        assertEquals(true, decodeBAD < 30)
    }
}