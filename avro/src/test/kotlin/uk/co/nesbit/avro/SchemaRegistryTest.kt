package uk.co.nesbit.avro

import org.apache.avro.Schema
import org.apache.avro.SchemaBuilder
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.SchemaRegistry.Companion.FingerprintHash
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.assertFailsWith

class SchemaRegistryTest {
    private val schema1 = SchemaBuilder.record("test1").fields().requiredInt("intField").endRecord()
    private val schema2 = SchemaBuilder.record("test2").fields().requiredInt("intField").endRecord()
    private val schema3 = SchemaBuilder.record("test1").fields().requiredInt("intField2").endRecord()

    private data class SchemaTest1(private val intField: Int) : AvroConvertible {
        constructor(testRecord: GenericRecord) : this(testRecord.getTyped<Int>("intField"))

        companion object {
            val testSchema: Schema = SchemaBuilder.record("test1").fields().requiredInt("intField").endRecord()
        }

        override fun toGenericRecord(): GenericRecord {
            val testRecord = GenericData.Record(testSchema)
            testRecord.putTyped("intField", intField)
            return testRecord
        }
    }

    private data class SchemaTest2(private val intField2: Int) : AvroConvertible {
        constructor(testRecord: GenericRecord) : this(testRecord.getTyped<Int>("intField2"))

        companion object {
            val testSchema: Schema = SchemaBuilder.record("test2").fields().requiredInt("intField2").endRecord()
        }

        override fun toGenericRecord(): GenericRecord {
            val testRecord = GenericData.Record(testSchema)
            testRecord.putTyped("intField2", intField2)
            return testRecord
        }
    }

    @Test
    fun `register some simple schemas`() {
        val registry = SchemaRegistry()
        val print1 = registry.registerSchema(schema1)
        assertArrayEquals(SchemaNormalization.parsingFingerprint(FingerprintHash, schema1), print1)
        val print2 = registry.registerSchema(schema2)
        assertArrayEquals(SchemaNormalization.parsingFingerprint(FingerprintHash, schema2), print2)
        val print3 = registry.registerSchema(schema3)
        assertArrayEquals(SchemaNormalization.parsingFingerprint(FingerprintHash, schema3), print3)
        val print4 = registry.registerSchema(schema1) // re-registration is safe
        assertTrue(print1 === print4) // returned fingerprints are cached copies
        assertTrue(print1 === registry.getFingerprint(schema1)) // returned fingerprints are cached copies
        assertTrue(print2 === registry.getFingerprint(schema2)) // returned fingerprints are cached copies
        assertTrue(print3 === registry.getFingerprint(schema3)) // returned fingerprints are cached copies
    }

    @Test
    fun `get by name test`() {
        val registry = SchemaRegistry()
        registry.registerSchema(schema1)
        registry.registerSchema(schema2)
        registry.registerSchema(schema3)
        registry.registerSchema(schema1) // duplicate registration is safe
        assertEquals(listOf(schema1, schema3), registry.getSchemas("test1"))
        assertEquals(listOf(schema2), registry.getSchemas("test2"))
        assertEquals(emptyList<Schema>(), registry.getSchemas("dummy"))
    }

    @Test
    fun `serialisation test`() {
        val registry = SchemaRegistry()
        val print1 = registry.registerDeserializer(SchemaTest1::class.java, SchemaTest1.testSchema)
        registry.registerSchema(schema2) // Already registered schema shouldn't cause problems
        val print2 = registry.registerDeserializer(SchemaTest2::class.java, SchemaTest2.testSchema)
        registry.registerSchema(schema3) // Schema only registration shouldn't cause problems
        val test1 = SchemaTest1(1)
        val serialized1 = test1.serialize()
        val deserialized1 = registry.deserialize(print1, serialized1)
        assertEquals(test1, deserialized1)
        val test2 = SchemaTest2(2)
        val serialized2 = test2.serialize()
        val deserialized2 = registry.deserialize(print2, serialized2)
        assertEquals(test2, deserialized2)
        assertFailsWith<IllegalArgumentException> { registry.deserialize(ByteArray(1), serialized1) }
        assertFailsWith<IllegalArgumentException> {
            registry.deserialize(
                registry.getFingerprint(schema3),
                serialized1
            )
        }
    }

    @Test
    fun `multi-threaded`() {
        val registry = SchemaRegistry()
        val failed = AtomicBoolean(false)
        val threads = (0..10).map {
            thread(start = false, name = it.toString()) {
                try {
                    for (x in 0 until 100) {
                        if (it and 1 == 0) {
                            registry.safeRegisterDeserializer(SchemaTest1::class.java, SchemaTest1.testSchema)
                            registry.safeRegisterDeserializer(SchemaTest2::class.java, SchemaTest2.testSchema)
                        } else {
                            registry.safeRegisterDeserializer(SchemaTest2::class.java, SchemaTest2.testSchema)
                            registry.safeRegisterDeserializer(SchemaTest1::class.java, SchemaTest1.testSchema)
                        }
                    }
                } catch (ex: Exception) {
                    failed.set(true)
                }
            }
        }
        threads.forEach {
            it.start()
        }
        threads.forEach {
            it.join(10000L)
        }
        assertEquals(false, failed.get())
    }
}