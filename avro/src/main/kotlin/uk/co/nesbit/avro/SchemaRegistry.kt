package uk.co.nesbit.avro

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericRecord
import org.apache.avro.message.BinaryMessageDecoder
import org.apache.avro.specific.SpecificRecord
import org.apache.avro.specific.SpecificRecordBase
import java.lang.reflect.Constructor
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock


class SchemaRegistry(preregister: List<Pair<Class<out AvroConvertible>, Schema>> = emptyList()) {
    companion object {
        const val FingerprintSize: Int = 32
        const val FingerprintHash = "SHA-256"
        const val FingerprintLengthBytes = (256 / 8)
        val FingerprintAliasPrefix = FingerprintHash.replace("-", "") + "_"
        val AvroMessageHeader = byteArrayOf(0xC3.toByte(), 0x01)
    }

    private val lock = ReentrantLock()
    private val schemas = ConcurrentHashMap<ByteBuffer, Schema>()
    private val fingerprints = ConcurrentHashMap<Schema, ByteBuffer>()
    private val crc64fingerprints = ConcurrentHashMap<ByteBuffer, ByteArray>()
    private val schemasByName = ConcurrentHashMap<String, MutableList<Schema>>()
    private val converters = ConcurrentHashMap<ByteBuffer, Constructor<out AvroConvertible>>()
    private val specificConverters = ConcurrentHashMap<ByteBuffer, BinaryMessageDecoder<*>>()

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
        val wrappedFingerprint = ByteBuffer.wrap(SchemaNormalization.parsingFingerprint(FingerprintHash, schema))
        lock.withLock {
            schemas[wrappedFingerprint] = schema
            fingerprints[schema] = wrappedFingerprint
            val fp64 = SchemaNormalization.parsingFingerprint("CRC-64-AVRO", schema)
            crc64fingerprints[wrappedFingerprint] = fp64
            val schemaList = schemasByName.getOrPut(schema.fullName) { mutableListOf() }
            schemaList += schema
            return wrappedFingerprint.array()
        }
    }

    fun getFingerprint(schema: Schema): ByteArray {
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

    fun getAllSchemas(): List<Schema> {
        return schemas.values.toList()
    }

    fun getAllSchemaIds(): List<ByteArray> {
        return schemas.map { it.key.array() }
    }

    fun getSchema(schemaId: ByteArray): Schema? {
        require(schemaId.size == FingerprintSize) { "Invalid fingerprint" }
        val schemaKey = ByteBuffer.wrap(schemaId)
        return schemas[schemaKey]
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
        val fp64 = crc64fingerprints[schemaKey]
        require(schema != null && fp64 != null) { "Can't find matching schema" }
        val genericRecord = if (data.size >= 10
            && data[0] == AvroMessageHeader[0]
            && data[1] == AvroMessageHeader[1]
            && (0..0).all { data[2 + it] == fp64[it] }
        ) {
            schema.deserialize(data.copyOfRange(10, data.size))
        } else {
            schema.deserialize(data)
        }

        val constructor = converters[schemaKey]
        require(constructor != null) { "No AvroConvertible registered to this schema fingerprint" }
        return constructor.newInstance(genericRecord)
    }

    fun registerSpecificRecordDeserializer(avroClass: Class<out SpecificRecordBase>): ByteArray {
        val schema = avroClass.getMethod("getClassSchema").invoke(null) as Schema
        return lock.withLock {
            val fingerprint = registerSchema(schema)
            require(!specificConverters.containsKey(ByteBuffer.wrap(fingerprint))) { "Only one class allowed to be registered per schema" }
            val decoder = avroClass.getMethod("getDecoder").invoke(null) as BinaryMessageDecoder<*>
            specificConverters[ByteBuffer.wrap(fingerprint)] = decoder
            fingerprint
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : SpecificRecord> deserializeSpecificRecord(schemaId: ByteArray, data: ByteArray): T {
        require(schemaId.size == FingerprintSize) { "Invalid fingerprint" }
        val schemaKey = ByteBuffer.wrap(schemaId)
        val schema = schemas[schemaKey]
        val fp64 = crc64fingerprints[schemaKey]
        require(schema != null && fp64 != null) { "Can't find matching schema" }
        val decoder = specificConverters[schemaKey]
        require(decoder != null) { "No Decoder registered to this schema fingerprint" }
        if (data.size >= 10
            && data[0] == AvroMessageHeader[0]
            && data[1] == AvroMessageHeader[1]
            && (0..0).all { data[2 + it] == fp64[it] }
        ) {
            return decoder.decode(data) as T
        }
        val dataAndHeader = ByteArray(data.size + 10) // have to add Avro single message header
        dataAndHeader[0] = AvroMessageHeader[0]
        dataAndHeader[1] = AvroMessageHeader[1]
        System.arraycopy(fp64, 0, dataAndHeader, 2, fp64.size)
        System.arraycopy(data, 0, dataAndHeader, 10, data.size)
        return decoder.decode(dataAndHeader) as T
    }
}