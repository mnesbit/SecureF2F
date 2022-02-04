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
        val serialized = filter.serialize()
        val deserialized = InvertibleBloomFilter.deserialize(serialized)
        assertEquals(filter, deserialized)
        val decode = filter.decode()
        assertEquals(true, decode.ok)
        assertEquals(true, decode.deleted.isEmpty())
        assertEquals(values, decode.added)
        val estimator = SizeEstimator.createSizeEstimatorRequest(values)
        val serializedEstimator = estimator.serialize()
        val deserializedEstimator = SizeEstimator.deserialize(serializedEstimator)
        assertEquals(estimator, deserializedEstimator)
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
        assertEquals(true, decodedBAD > 0, "decode fail rate shouldn't be 0")
        assertEquals(true, decodedBAD < 170, "decode fail rate too high $decodedBAD")
        assertEquals(true, decodedOK > 240, "decode rate below target $decodedOK")
    }

    @Test
    fun `threshold test2`() {
        val random = Random()
        for (size in listOf(0, 10, 20, 50, 60)) { // beginning of the drop-off zone
            var decodedOK = 0
            val values1 = (0 until 8000).toSet()
            val values2 = (size until (8000 + size)).toSet()
            for (rep in 0 until 100) {
                val filter1 = InvertibleBloomFilter(random.nextInt(), 200)
                for (value in values1) {
                    filter1.add(value)
                }
                val decoded = filter1.decode(values2)
                if (decoded.ok) {
                    assertEquals(values1.minus(values2), decoded.added)
                    assertEquals(values2.minus(values1), decoded.deleted)
                    ++decodedOK
                }
            }
            assertEquals(true, decodedOK > 85, "decode rate below target $decodedOK")
        }
    }

    @Test
    fun `test size independence`() {
        val random = Random()
        for (scale in 1..10) {
            var decodedOK = 0
            val size = 1000 shl scale
            val values1 = (0 until size).toSet()
            val values2 = (50 until (50 + size)).toSet()
            for (rep in 0 until 20) {
                val filter1 = InvertibleBloomFilter(random.nextInt(), 400)
                for (value in values1) {
                    filter1.add(value)
                }
                val decoded = filter1.decode(values2)
                if (decoded.ok) {
                    assertEquals(values1.minus(values2), decoded.added)
                    assertEquals(values2.minus(values1), decoded.deleted)
                    ++decodedOK
                }
            }
            assertEquals(true, decodedOK > 17, "decode rate below target $decodedOK")
        }
    }

    @Test
    fun `estimator test`() {
        for (i in listOf(0, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000)) {
            var decodedOK = 0
            val values1 = (0 until 10000).toSet()
            val values2 = (i until (10000 + i)).toSet()
            for (rep in 0 until 100) {
                val estimator = SizeEstimator.createSizeEstimatorRequest(values1)
                val response = estimator.calculateResponse(values2)
                val decode = response.decode(values1)
                if (decode.ok) {
                    ++decodedOK
                    assertEquals(values1.minus(values2), decode.deleted)
                    assertEquals(values2.minus(values1), decode.added)
                }
            }
            assertEquals(true, decodedOK > 75, "decode rate below target $decodedOK")
        }
    }
}