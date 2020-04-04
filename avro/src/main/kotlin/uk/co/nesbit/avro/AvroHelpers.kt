package uk.co.nesbit.avro

import org.apache.avro.Conversions
import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.*
import org.apache.avro.io.EncoderFactory
import org.apache.avro.util.Utf8
import uk.co.nesbit.utils.printHexBinary
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigDecimal
import java.nio.ByteBuffer
import java.time.*
import java.util.*

fun resolveSchemas(schemas: List<String>): Map<String, Schema> {
    val unprocessed = schemas.toMutableList()
    var parser = Schema.Parser()
    val types = LinkedHashMap<String, Schema>()
    var lastError: Exception? = null
    while (!unprocessed.isEmpty()) {
        var progress = false
        val iter = unprocessed.listIterator()
        while (iter.hasNext()) {
            val newSchema = iter.next()
            try {
                parser.parse(newSchema)
                for (typePair in parser.types) {
                    if (!types.containsKey(typePair.key)) {
                        val hash = SchemaNormalization.parsingFingerprint("SHA-256", typePair.value)
                        val sig = "hashed.H" + hash.printHexBinary()
                        typePair.value.addAlias(sig)
                        types[typePair.key] = typePair.value
                    }
                }
                iter.remove()
                progress = true
            } catch (ex: Exception) {
                lastError = ex
                // reset parser
                parser = Schema.Parser()
                parser.addTypes(types)
            }
        }
        if (!progress) {
            throw IllegalArgumentException("Unable to resolve schemas", lastError)
        }
    }
    return types
}

fun GenericRecord.serialize(): ByteArray {
    val datumWriter = GenericDatumWriter<GenericRecord>(this.schema)
    val byteStream = ByteArrayOutputStream()
    byteStream.use {
        val encoder = EncoderFactory.get().binaryEncoder(byteStream, null)
        datumWriter.write(this, encoder)
        encoder.flush()
        byteStream.flush()
        return byteStream.toByteArray()
    }
}

fun GenericArray<GenericRecord>.serialize(): ByteArray {
    val datumWriter = GenericDatumWriter<GenericArray<GenericRecord>>(this.schema)
    val byteStream = ByteArrayOutputStream()
    byteStream.use {
        val encoder = EncoderFactory.get().binaryEncoder(byteStream, null)
        datumWriter.write(this, encoder)
        encoder.flush()
        byteStream.flush()
        return byteStream.toByteArray()
    }
}

typealias AvroEncoder<T> = (T) -> GenericRecord
typealias AvroDecoder<T> = (GenericRecord) -> T

object AvroTypeHelpers {
    val helpers = mutableMapOf<Class<*>, Pair<AvroEncoder<*>, AvroDecoder<*>>>()

    fun <T> registerHelper(clazz: Class<T>, encoder: AvroEncoder<T>, decoder: AvroDecoder<T>) {
        helpers[clazz] = Pair(encoder, decoder)
    }
}

fun Schema.deserialize(bytes: ByteArray): GenericRecord {
    val datumReader = GenericDatumReader<GenericRecord>(this)
    val decoder = SafeDecoder(bytes)
    val record = datumReader.read(null, decoder)
    if (!decoder.fullyConsumed) {
        throw IOException()
    }
    return record
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T> GenericRecord.getTyped(fieldName: String): T {
    val value = this.get(fieldName) ?: return null as T
    val pluginHandlers = AvroTypeHelpers.helpers[T::class.java]
    if (pluginHandlers != null) {
        return pluginHandlers.second(value as GenericRecord) as T
    }
    if (T::class.java.isEnum) {
        val enumString = (value as GenericEnumSymbol<*>).toString()
        @Suppress("UPPER_BOUND_VIOLATED", "UNCHECKED_CAST")
        return java.lang.Enum.valueOf<T>(T::class.java, enumString)
    }
    when (T::class.java) {
        String::class.java -> {
            return value.toString() as T
        }
        ByteArray::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            return if (fieldSchema.type == Schema.Type.FIXED) {
                (value as GenericData.Fixed).bytes().copyOf() as T
            } else {
                (value as ByteBuffer).array().copyOf() as T
            }
        }
        BigDecimal::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            return Conversions.DecimalConversion().fromBytes(get(fieldName) as ByteBuffer, fieldSchema, fieldSchema.logicalType) as T
        }
        UUID::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            return Conversions.UUIDConversion().fromCharSequence(get(fieldName) as CharSequence, fieldSchema, fieldSchema.logicalType) as T
        }
        Instant::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                return when (fieldSchema.logicalType.name) {
                    "date" -> {
                        LocalDate.ofEpochDay((get(fieldName) as Int).toLong()).atStartOfDay().toInstant(ZoneOffset.UTC) as T
                    }
                    "timestamp-millis" -> {
                        Instant.ofEpochMilli(get(fieldName) as Long) as T
                    }
                    "timestamp-micros" -> {
                        val micros = get(fieldName) as Long
                        Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L)) as T
                    }
                    else -> {
                        Instant.ofEpochMilli(get(fieldName) as Long) as T
                    }
                }
            } else {
                return Instant.ofEpochMilli(get(fieldName) as Long) as T
            }
        }
        LocalDateTime::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                return when (fieldSchema.logicalType.name) {
                    "date" -> {
                        LocalDate.ofEpochDay((get(fieldName) as Int).toLong()).atStartOfDay() as T
                    }
                    "timestamp-millis" -> {
                        LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC) as T
                    }
                    "timestamp-micros" -> {
                        val micros = get(fieldName) as Long
                        LocalDateTime.ofInstant(Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L)), ZoneOffset.UTC) as T
                    }
                    else -> {
                        LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC) as T
                    }
                }
            } else {
                return LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC) as T
            }
        }
        LocalDate::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                when (fieldSchema.logicalType.name) {
                    "date" -> {
                        return LocalDate.ofEpochDay((get(fieldName) as Int).toLong()) as T
                    }
                    "timestamp-millis" -> {
                        val instant = Instant.ofEpochMilli(get(fieldName) as Long)
                        return LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate() as T
                    }
                    "timestamp-micros" -> {
                        val micros = get(fieldName) as Long
                        val instant = Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L))
                        return LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate() as T
                    }
                    else -> {
                        return LocalDate.ofEpochDay((get(fieldName) as Int).toLong()) as T
                    }
                }
            } else {
                return LocalDate.ofEpochDay((get(fieldName) as Int).toLong()) as T
            }
        }
        LocalTime::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            return if (fieldSchema.logicalType != null) {
                when (fieldSchema.logicalType.name) {
                    "time-millis" -> {
                        LocalTime.ofNanoOfDay((get(fieldName) as Int).toLong() * 1000000L) as T
                    }
                    "time-micros" -> {
                        LocalTime.ofNanoOfDay((get(fieldName) as Long) * 1000L) as T
                    }
                    else -> {
                        LocalTime.ofNanoOfDay((get(fieldName) as Int).toLong() * 1000000L) as T
                    }
                }
            } else {
                LocalTime.ofNanoOfDay((get(fieldName) as Int).toLong() * 1000000L) as T
            }
        }
    }
    return (value as T)
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T> GenericRecord.getTyped(fieldName: String, constructor: (GenericRecord) -> T): T {
    val field = get(fieldName) as GenericRecord?
    if ((field == null) && (null is T)) {
        return null as T
    }
    return constructor(field!!)
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.getGenericArray(fieldName: String, schema: Schema): List<GenericRecord> {
    return (get(fieldName) as GenericArray<ByteBuffer>).map { schema.deserialize(it.array()) }
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T : Any> GenericRecord.getObjectArray(fieldName: String, constructor: (GenericRecord) -> T): List<T> {
    return (get(fieldName) as GenericArray<GenericRecord>).map { constructor(it) }
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T> GenericRecord.putTyped(fieldName: String, value: T) {
    when (value) {
        is AvroConvertible -> {
            put(fieldName, value.toGenericRecord())
            return
        }
        null -> {
            put(fieldName, null)
            return
        }
    }
    val pluginHandlers = AvroTypeHelpers.helpers[T::class.java]
    if (pluginHandlers != null) {
        val encoder = pluginHandlers.first as AvroEncoder<T>
        put(fieldName, encoder(value))
        return
    }
    if (T::class.java.isEnum) {
        val fieldSchema = schema.getField(fieldName).schema()
        val enumRecord = GenericData.EnumSymbol(fieldSchema, value)
        put(fieldName, enumRecord)
        return
    }
    when (T::class.java) {
        String::class.java -> {
            put(fieldName, Utf8(value as String))
        }
        ByteArray::class.java -> {
            val bytes = value as ByteArray
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.type == Schema.Type.FIXED) {
                require(bytes.size == fieldSchema.fixedSize) { "Fixed field requires input of size ${fieldSchema.fixedSize} not ${bytes.size}" }
                put(fieldName, GenericData.Fixed(fieldSchema, bytes))
            } else {
                val buffer = ByteBuffer.wrap(bytes)
                put(fieldName, buffer)
            }
        }
        BigDecimal::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            val bytes = Conversions.DecimalConversion().toBytes(value as BigDecimal, fieldSchema, fieldSchema.logicalType)
            put(fieldName, bytes)
        }
        UUID::class.java -> {
            val fieldSchema = schema.getField(fieldName).schema()
            val uuidString = Conversions.UUIDConversion().toCharSequence(value as UUID, fieldSchema, fieldSchema.logicalType)
            put(fieldName, uuidString)
        }
        Instant::class.java -> {
            val instant = value as Instant
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                when (fieldSchema.logicalType.name) {
                    "date" -> {
                        val date = LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate()
                        put(fieldName, date.toEpochDay().toInt())
                    }
                    "time-millis" -> {
                        val time = LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalTime()
                        put(fieldName, (time.toNanoOfDay() / 1000000L).toInt())
                    }
                    "time-micros" -> {
                        val time = LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalTime()
                        put(fieldName, time.toNanoOfDay() / 1000L)
                    }
                    "timestamp-millis" -> {
                        put(fieldName, instant.toEpochMilli())
                    }
                    "timestamp-micros" -> {
                        val micros = (instant.epochSecond * 1000000L) + (instant.nano / 1000L)
                        put(fieldName, micros)
                    }
                    else -> {
                        put(fieldName, instant.toEpochMilli())
                    }
                }
            } else {
                put(fieldName, instant.toEpochMilli())
            }
        }
        LocalDate::class.java -> {
            val date = value as LocalDate
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                when (fieldSchema.logicalType.name) {
                    "date" -> {
                        put(fieldName, date.toEpochDay().toInt())
                    }
                    "timestamp-millis" -> {
                        put(fieldName, date.toEpochDay() * 86400000L)
                    }
                    "timestamp-micros" -> {
                        put(fieldName, date.toEpochDay() * 86400000000L)
                    }
                    else -> {
                        put(fieldName, date.toEpochDay().toInt())
                    }
                }
            } else {
                put(fieldName, date.toEpochDay().toInt())
            }
        }
        LocalTime::class.java -> {
            val time = value as LocalTime
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                when (fieldSchema.logicalType.name) {
                    "time-millis" -> {
                        put(fieldName, (time.toNanoOfDay() / 1000000L).toInt())
                    }
                    "time-micros" -> {
                        put(fieldName, time.toNanoOfDay() / 1000L)

                    }
                    else -> {
                        put(fieldName, (time.toNanoOfDay() / 1000000L).toInt())
                    }
                }
            } else {
                put(fieldName, (time.toNanoOfDay() / 1000000L).toInt())
            }
        }
        LocalDateTime::class.java -> {
            val dateTime = value as LocalDateTime
            val fieldSchema = schema.getField(fieldName).schema()
            if (fieldSchema.logicalType != null) {
                when (fieldSchema.logicalType.name) {
                    "date" -> {
                        put(fieldName, dateTime.toLocalDate().toEpochDay().toInt())
                    }
                    "time-millis" -> {
                        put(fieldName, (dateTime.toLocalTime().toNanoOfDay() / 1000000L).toInt())
                    }
                    "time-micros" -> {
                        put(fieldName, dateTime.toLocalTime().toNanoOfDay() / 1000L)
                    }
                    "timestamp-millis" -> {
                        put(fieldName, dateTime.toInstant(ZoneOffset.UTC).toEpochMilli())
                    }
                    "timestamp-micros" -> {
                        val instant = dateTime.toInstant(ZoneOffset.UTC)
                        val micros = (instant.epochSecond * 1000000L) + (instant.nano / 1000L)
                        put(fieldName, micros)
                    }
                    else -> {
                        put(fieldName, dateTime.toInstant(ZoneOffset.UTC).toEpochMilli().toInt())
                    }
                }
            } else {
                put(fieldName, dateTime.toInstant(ZoneOffset.UTC).toEpochMilli())
            }
        }
        else -> {
            put(fieldName, value)
        }
    }
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.putGenericArray(fieldName: String, value: List<GenericRecord>) {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.ARRAY) { "putGenericArray only works on Array fields" }
    val arrayElementType = fieldSchema.elementType.type
    when (arrayElementType) {
        Schema.Type.RECORD -> {
            val arrayData = GenericData.Array<GenericRecord>(fieldSchema, value.map { it })
            put(fieldName, arrayData)
        }
        Schema.Type.BYTES -> {
            val arrayData = GenericData.Array<ByteBuffer>(fieldSchema, value.map { ByteBuffer.wrap(it.serialize()) })
            put(fieldName, arrayData)
        }
        else -> throw IllegalArgumentException("putGenericArray only applies to Array<GenericRecord> and Array<ByteBuffer> fields")
    }
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T : AvroConvertible> GenericRecord.putObjectArray(fieldName: String, value: List<T>) {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.ARRAY) { "putObjectArray only works on Array fields" }
    val arrayElementType = fieldSchema.elementType.type
    when (arrayElementType) {
        Schema.Type.RECORD -> {
            val arrayData = GenericData.Array<GenericRecord>(fieldSchema, value.map { it.toGenericRecord() })
            put(fieldName, arrayData)
        }
        Schema.Type.BYTES -> {
            val arrayData = GenericData.Array<ByteBuffer>(fieldSchema, value.map { ByteBuffer.wrap(it.serialize()) })
            put(fieldName, arrayData)
        }
        else -> throw IllegalArgumentException("putObjectArray only applies to Array<GenericRecord> and Array<ByteBuffer> fields")
    }
}


enum class AvroExtendedType {
    RECORD,
    ENUM,
    ARRAY,
    MAP,
    UNION,
    FIXED,
    STRING,
    BYTES,
    INT,
    LONG,
    FLOAT,
    DOUBLE,
    BOOLEAN,
    NULL,
    DECIMAL,
    UUID,
    DATE,
    TIME_MILLIS,
    TIME_MICROS,
    TIMESTAMP_MILLIS,
    TIMESTAMP_MICROS,
    UNKNOWN
}


fun Schema.getExtendedType(): AvroExtendedType {
    if (logicalType != null) {
        when (logicalType.name) {
            "decimal" -> {
                return AvroExtendedType.DECIMAL
            }
            "uuid" -> {
                return AvroExtendedType.UUID
            }
            "date" -> {
                return AvroExtendedType.DATE
            }
            "time-millis" -> {
                return AvroExtendedType.TIME_MILLIS
            }
            "time-micros" -> {
                return AvroExtendedType.TIME_MICROS
            }
            "timestamp-millis" -> {
                return AvroExtendedType.TIMESTAMP_MILLIS
            }
            "timestamp-micros" -> {
                return AvroExtendedType.TIMESTAMP_MICROS
            }
            else -> {
                return AvroExtendedType.UNKNOWN
            }
        }
    }
    when (type) {
        Schema.Type.RECORD -> {
            return AvroExtendedType.RECORD
        }
        Schema.Type.ENUM -> {
            return AvroExtendedType.ENUM
        }
        Schema.Type.ARRAY -> {
            return AvroExtendedType.ARRAY
        }
        Schema.Type.MAP -> {
            return AvroExtendedType.MAP
        }
        Schema.Type.UNION -> {
            return AvroExtendedType.UNION
        }
        Schema.Type.FIXED -> {
            return AvroExtendedType.FIXED
        }
        Schema.Type.STRING -> {
            return AvroExtendedType.STRING
        }
        Schema.Type.BYTES -> {
            return AvroExtendedType.BYTES
        }
        Schema.Type.INT -> {
            return AvroExtendedType.INT
        }
        Schema.Type.LONG -> {
            return AvroExtendedType.LONG
        }
        Schema.Type.FLOAT -> {
            return AvroExtendedType.FLOAT
        }
        Schema.Type.DOUBLE -> {
            return AvroExtendedType.DOUBLE
        }
        Schema.Type.BOOLEAN -> {
            return AvroExtendedType.BOOLEAN
        }
        Schema.Type.NULL -> {
            return AvroExtendedType.NULL
        }
        else -> {
            return AvroExtendedType.UNKNOWN
        }
    }
}