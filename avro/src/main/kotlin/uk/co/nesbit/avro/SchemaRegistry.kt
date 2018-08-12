package uk.co.nesbit.avro

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.utils.ThreadSafeState
import java.lang.reflect.Constructor
import java.nio.ByteBuffer

class SchemaRegistry {
    private class RegistryState {
        val schemas = mutableMapOf<ByteBuffer, Schema>()
        val fingerprints = mutableMapOf<Schema, ByteBuffer>()
        val schemasByName = mutableMapOf<String, MutableList<Schema>>()
        val converters = mutableMapOf<ByteBuffer, Constructor<out AvroConvertible>>()
    }

    private val state = ThreadSafeState(RegistryState())

    fun registerSchema(schema: Schema): ByteArray {
        state.locked {
            val fingerprint = fingerprints[schema]
            if (fingerprint != null) {
                return fingerprint.array()
            }
            val wrappedFingerprint = ByteBuffer.wrap(SchemaNormalization.parsingFingerprint("SHA-256", schema))
            schemas[wrappedFingerprint] = schema
            fingerprints[schema] = wrappedFingerprint
            val schemaList = schemasByName.getOrPut(schema.fullName, { mutableListOf() })
            schemaList += schema
            return wrappedFingerprint.array()
        }
    }

    fun getFingeprint(schema: Schema): ByteArray = state.locked {
        fingerprints[schema]?.array() ?: registerSchema(schema)
    }

    fun getSchemas(schemaName: String): List<Schema> = state.locked { schemasByName[schemaName] ?: emptyList() }

    fun <T : AvroConvertible> registerDeserializer(convertibleClass: Class<T>, schema: Schema): ByteArray {
        state.locked {
            val fingerprint = getFingeprint(schema)
            require(!converters.containsKey(ByteBuffer.wrap(fingerprint))) { "Only one class allowed to be registered per schema" }
            val constructor = convertibleClass.getConstructor(GenericRecord::class.java)
            require(constructor != null) { "No constructor from GenericRecord found" }
            converters[ByteBuffer.wrap(fingerprint)] = constructor
            return fingerprint
        }
    }

    fun deserialize(schemaId: ByteArray, data: ByteArray): AvroConvertible {
        state.locked {
            require(schemaId.size == 32) { "Invalid fingerprint" }
            val schemaKey = ByteBuffer.wrap(schemaId)
            val schema = schemas[schemaKey]
            require(schema != null) { "Can't find matching schema" }
            val genericRecord = schema!!.deserialize(data)
            val constructor = converters[schemaKey]
            require(constructor != null) { "No AvroConvertible registered to this schema fingerprint" }
            return constructor!!.newInstance(genericRecord)
        }
    }
}