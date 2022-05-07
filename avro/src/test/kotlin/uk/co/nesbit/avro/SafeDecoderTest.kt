package uk.co.nesbit.avro

import org.apache.avro.SchemaBuilder
import org.apache.avro.generic.GenericData
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.*
import kotlin.experimental.xor
import kotlin.test.assertFailsWith

class SafeDecoderTest {
    @Test
    fun `Int test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema = schemaBuilder.record("Simple").fields().requiredInt("IntField").endRecord()
        fun encodeDecode(i: Int): Pair<ByteArray, Int> {
            val record = GenericData.Record(schema)
            record.putTyped("IntField", i)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<Int>("IntField")
            return Pair(serialized, field)
        }

        for (i in -512..+512) {
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127..+128) {
            val i = (x shl 8) or 0xA1
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127..+128) {
            val i = (x shl 16) or 0xAAA1
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127..+128) {
            val i = (x shl 24) or 0xAAAAA1
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        val (serializedMin, fieldMin) = encodeDecode(Int.MIN_VALUE)
        assertEquals(Int.MIN_VALUE, fieldMin)
        assertFailsWith<IOException> {
            schema.deserialize(serializedMin.copyOf(serializedMin.size - 1))
        }
        val (serializedMax, fieldMax) = encodeDecode(Int.MAX_VALUE)
        assertEquals(Int.MAX_VALUE, fieldMax)
        assertFailsWith<IOException> {
            schema.deserialize(serializedMax.copyOf(serializedMax.size - 1))
        }
    }

    @Test
    fun `Long test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema = schemaBuilder.record("Simple").fields().requiredLong("LongField").endRecord()
        fun encodeDecode(i: Long): Pair<ByteArray, Long> {
            val record = GenericData.Record(schema)
            record.putTyped("LongField", i)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<Long>("LongField")
            return Pair(serialized, field)
        }

        for (i in -512L..+512L) {
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127L..+128L) {
            val i = (x shl 8) or 0xA1L
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127L..+128L) {
            val i = (x shl 24) or 0xAAAAA1L
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127L..+128L) {
            val i = (x shl 32) or 0xAAAAAAA1L
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127L..+128L) {
            val i = (x shl 48) or 0xAAAAAAAAAAA1L
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        for (x in -127L..+128L) {
            val i = (x shl 56) or 0xAAAAAAAAAAAAA1L
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        val (serializedMin, fieldMin) = encodeDecode(Long.MIN_VALUE)
        assertEquals(Long.MIN_VALUE, fieldMin)
        assertFailsWith<IOException> {
            schema.deserialize(serializedMin.copyOf(serializedMin.size - 1))
        }
        val (serializedMax, fieldMax) = encodeDecode(Long.MAX_VALUE)
        assertEquals(Long.MAX_VALUE, fieldMax)
        assertFailsWith<IOException> {
            schema.deserialize(serializedMax.copyOf(serializedMax.size - 1))
        }
    }

    @Test
    fun `Float Test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema = schemaBuilder.record("Simple").fields().requiredFloat("FloatField").endRecord()
        fun encodeDecode(i: Float): Pair<ByteArray, Float> {
            val record = GenericData.Record(schema)
            record.putTyped("FloatField", i)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<Float>("FloatField")
            return Pair(serialized, field)
        }

        for (x in -512..+512) {
            val i = x.toFloat()
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        val random = Random()
        for (x in 0..100) {
            val i = random.nextFloat()
            val (serialized, field) = encodeDecode(i)
            assertEquals(i, field)
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        val (serializedMin, fieldMin) = encodeDecode(Float.MIN_VALUE)
        assertEquals(Float.MIN_VALUE, fieldMin)
        assertFailsWith<IOException> {
            schema.deserialize(serializedMin.copyOf(serializedMin.size - 1))
        }
        val (serializedMax, fieldMax) = encodeDecode(Float.MAX_VALUE)
        assertEquals(Float.MAX_VALUE, fieldMax)
        assertFailsWith<IOException> {
            schema.deserialize(serializedMax.copyOf(serializedMax.size - 1))
        }
        val (serializedNan, fieldNan) = encodeDecode(Float.NaN)
        assertEquals(Float.NaN, fieldNan)
        assertFailsWith<IOException> {
            schema.deserialize(serializedNan.copyOf(serializedNan.size - 1))
        }
        val (serializedPInf, fieldPInf) = encodeDecode(Float.POSITIVE_INFINITY)
        assertEquals(Float.POSITIVE_INFINITY, fieldPInf)
        assertFailsWith<IOException> {
            schema.deserialize(serializedPInf.copyOf(serializedPInf.size - 1))
        }
        val (serializedNInf, fieldNInf) = encodeDecode(Float.NEGATIVE_INFINITY)
        assertEquals(Float.NEGATIVE_INFINITY, fieldNInf)
        assertFailsWith<IOException> {
            schema.deserialize(serializedNInf.copyOf(serializedNInf.size - 1))
        }
    }

    @Test
    fun `Double Test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema = schemaBuilder.record("Simple").fields().requiredDouble("DoubleField").endRecord()
        fun encodeDecode(i: Double): Pair<ByteArray, Double> {
            val record = GenericData.Record(schema)
            record.putTyped("DoubleField", i)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<Double>("DoubleField")
            return Pair(serialized, field)
        }

        for (x in -512..+512) {
            val i = x.toDouble()
            val (serialized, field) = encodeDecode(i)
            assertEquals(i.toRawBits(), field.toRawBits())
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        val random = Random()
        for (x in 0..100) {
            val i = random.nextDouble()
            val (serialized, field) = encodeDecode(i)
            assertEquals(i.toRawBits(), field.toRawBits())
            assertFailsWith<IOException> {
                schema.deserialize(serialized.copyOf(serialized.size - 1))
            }
        }
        val (serializedMin, fieldMin) = encodeDecode(Double.MIN_VALUE)
        assertEquals(Double.MIN_VALUE.toRawBits(), fieldMin.toRawBits())
        assertFailsWith<IOException> {
            schema.deserialize(serializedMin.copyOf(serializedMin.size - 1))
        }
        val (serializedMax, fieldMax) = encodeDecode(Double.MAX_VALUE)
        assertEquals(Double.MAX_VALUE.toRawBits(), fieldMax.toRawBits())
        assertFailsWith<IOException> {
            schema.deserialize(serializedMax.copyOf(serializedMax.size - 1))
        }
        val (serializedNan, fieldNan) = encodeDecode(Double.NaN)
        assertEquals(Double.NaN.toRawBits(), fieldNan.toRawBits())
        assertFailsWith<IOException> {
            schema.deserialize(serializedNan.copyOf(serializedNan.size - 1))
        }
        val (serializedPInf, fieldPInf) = encodeDecode(Double.POSITIVE_INFINITY)
        assertEquals(Double.POSITIVE_INFINITY.toRawBits(), fieldPInf.toRawBits())
        assertFailsWith<IOException> {
            schema.deserialize(serializedPInf.copyOf(serializedPInf.size - 1))
        }
        val (serializedNInf, fieldNInf) = encodeDecode(Double.NEGATIVE_INFINITY)
        assertEquals(Double.NEGATIVE_INFINITY.toRawBits(), fieldNInf.toRawBits())
        assertFailsWith<IOException> {
            schema.deserialize(serializedNInf.copyOf(serializedNInf.size - 1))
        }
    }

    @Test
    fun `Fixed test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema = schemaBuilder.record("Simple").fields().name("FixedField").type().fixed("X").size(16).noDefault()
            .endRecord()

        fun encodeDecode(f: ByteArray): Pair<ByteArray, ByteArray> {
            val record = GenericData.Record(schema)
            record.putTyped("FixedField", f)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<ByteArray>("FixedField")
            return Pair(serialized, field)
        }

        val random = Random()
        val fixed16 = ByteArray(16)
        random.nextBytes(fixed16)
        val (serialized, field) = encodeDecode(fixed16)
        assertArrayEquals(fixed16, field)
        assertFailsWith<IOException> {
            schema.deserialize(serialized.copyOf(serialized.size - 1))
        }
    }

    @Test
    fun `Bytes test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema =
            schemaBuilder.record("Simple").fields().name("BytesField").type().bytesType().noDefault().endRecord()

        fun encodeDecode(b: ByteArray): Pair<ByteArray, ByteArray> {
            val record = GenericData.Record(schema)
            record.putTyped("BytesField", b)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<ByteArray>("BytesField")
            return Pair(serialized, field)
        }

        val random = Random()
        val bytes = ByteArray(100)
        random.nextBytes(bytes)
        val (serialized, field) = encodeDecode(bytes)
        assertArrayEquals(bytes, field)
        assertFailsWith<IOException> {
            schema.deserialize(serialized.copyOf(serialized.size - 1))
        }
        for (i in 0 until 8) {
            val mask = (1 shl i).toByte()
            serialized[0] = serialized[0] xor mask
            assertFailsWith<IOException> {
                schema.deserialize(serialized)
            }
            serialized[0] = serialized[0] xor mask
            serialized[1] = serialized[1] xor mask
            assertFailsWith<IOException> {
                schema.deserialize(serialized)
            }
            serialized[1] = serialized[1] xor mask
        }
    }

    @Test
    fun `String test`() {
        val schemaBuilder = SchemaBuilder.builder("test")
        val schema =
            schemaBuilder.record("Simple").fields().name("StringField").type().stringType().noDefault().endRecord()

        fun encodeDecode(s: String): Pair<ByteArray, String> {
            val record = GenericData.Record(schema)
            record.putTyped("StringField", s)
            val serialized = record.serialize()
            val deserialized = schema.deserialize(serialized)
            val field = deserialized.getTyped<String>("StringField")
            return Pair(serialized, field)
        }

        val str = "\uFF00This is a Test\u3066\u1234\nBeep"
        val (serialized, field) = encodeDecode(str)
        assertEquals(str, field)
        assertFailsWith<IOException> {
            schema.deserialize(serialized.copyOf(serialized.size - 1))
        }
        for (i in 0 until 8) {
            val mask = (1 shl i).toByte()
            serialized[0] = serialized[0] xor mask
            assertFailsWith<IOException> {
                schema.deserialize(serialized)
            }
            serialized[0] = serialized[0] xor mask
        }
    }
}