package uk.co.nesbit.avro

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericRecord
import java.lang.reflect.Constructor
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class SchemaRegistry(preregister: List<Pair<Class<out AvroConvertible>, Schema>> = emptyList()) {
    companion object {
        const val FingerprintSize: Int = 32
    }

    val lock = ReentrantLock()
    val schemas = ConcurrentHashMap<ByteBuffer, Schema>()
    val fingerprints = ConcurrentHashMap<Schema, ByteBuffer>()
    val schemasByName = ConcurrentHashMap<String, MutableList<Schema>>()
    val converters = ConcurrentHashMap<ByteBuffer, Constructor<out AvroConvertible>>()

    init {
        for (item in preregister) {
            registerDeserializer(item.first, item.second)
        }
    }

    fun registerSchema(schema: Schema): ByteArray {
        val fingerprint = fingerprints[schema]
        if (fingerprint != null) {
            return fingerprint.array()
        }
        val wrappedFingerprint = ByteBuffer.wrap(SchemaNormalization.parsingFingerprint("SHA-256", schema))
        lock.withLock {
            schemas[wrappedFingerprint] = schema
            fingerprints[schema] = wrappedFingerprint
            val schemaList = schemasByName.getOrPut(schema.fullName, { mutableListOf() })
            schemaList += schema
            return wrappedFingerprint.array()
        }
    }

    fun getFingeprint(schema: Schema): ByteArray {
        val fingerprint = fingerprints[schema]
        if (fingerprint != null) {
            return fingerprint.array()
        }
        lock.withLock {
            return registerSchema(schema)
        }
    }

    fun getSchemas(schemaName: String): List<Schema> {
        return schemasByName[schemaName] ?: emptyList()
    }

    fun <T : AvroConvertible> safeRegisterDeserializer(convertibleClass: Class<T>, schema: Schema): ByteArray {
        val fingerprint = fingerprints[schema]
        if (fingerprint != null) {
            return fingerprint.array()
        }
        lock.withLock {
            val fingerprintOld = fingerprints[schema]
            if (fingerprintOld != null) {
                return fingerprintOld.array()
            }
            return registerDeserializer(convertibleClass, schema)
        }
    }

    fun <T : AvroConvertible> registerDeserializer(convertibleClass: Class<T>, schema: Schema): ByteArray {
        return lock.withLock {
            val fingerprint = registerSchema(schema)
            require(!converters.containsKey(ByteBuffer.wrap(fingerprint))) { "Only one class allowed to be registered per schema" }
            val constructor = try {
                convertibleClass.getConstructor(GenericRecord::class.java)
            } catch (ex: NoSuchMethodException) {
                throw IllegalArgumentException("No constructor from GenericRecord found", ex)
            }
            converters[ByteBuffer.wrap(fingerprint)] = constructor
            fingerprint
        }
    }

    fun deserialize(schemaId: ByteArray, data: ByteArray): AvroConvertible {
        require(schemaId.size == FingerprintSize) { "Invalid fingerprint" }
        val schemaKey = ByteBuffer.wrap(schemaId)
        val schema = schemas[schemaKey]
        require(schema != null) { "Can't find matching schema" }
        val genericRecord = schema.deserialize(data)
        val constructor = converters[schemaKey]
        require(constructor != null) { "No AvroConvertible registered to this schema fingerprint" }
        return constructor.newInstance(genericRecord)
    }
}