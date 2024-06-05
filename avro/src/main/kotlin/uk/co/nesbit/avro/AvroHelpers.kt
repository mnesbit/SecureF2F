package uk.co.nesbit.avro

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.avro.AvroTypeException
import org.apache.avro.Conversions
import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.*
import org.apache.avro.io.DecoderFactory
import org.apache.avro.io.EncoderFactory
import org.apache.avro.util.Utf8
import uk.co.nesbit.utils.printHexBinary
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigDecimal
import java.nio.ByteBuffer
import java.time.*
import java.util.*

fun collectSchemaImportTypes(json: JsonNode): Set<String> {
    val schemas = mutableSetOf<String>()
    val declaredTypes = mutableSetOf<String>()
    collectSchemaImportTypes(json, "", schemas, declaredTypes)
    return schemas - declaredTypes
}

private fun collectSchemaImportTypes(
    json: JsonNode,
    namespace: String,
    schemas: MutableSet<String>,
    declaredTypes: MutableSet<String>
) {
    if (json.isObject) {
        val type = json["type"]
        if (type.isObject) {
            collectSchemaImportTypes(type, namespace, schemas, declaredTypes)
        } else if (type.isArray) {
            for (item in type.iterator()) {
                collectSchemaImportTypes(item, namespace, schemas, declaredTypes)
            }
        } else {
            when (val typeString = type.textValue()) {
                Schema.Type.NULL.getName(),
                Schema.Type.BOOLEAN.getName(),
                Schema.Type.INT.getName(),
                Schema.Type.LONG.getName(),
                Schema.Type.BYTES.getName(),
                Schema.Type.STRING.getName(),
                Schema.Type.FLOAT.getName(),
                Schema.Type.DOUBLE.getName() -> {
                    // ignore
                }

                Schema.Type.FIXED.getName(),
                Schema.Type.ENUM.getName() -> {
                    val newNamespace = if (json.has("namespace")) {
                        json["namespace"].textValue()
                    } else {
                        namespace
                    }
                    val name = json["name"].textValue()
                    declaredTypes += if (name.contains(".") || newNamespace == "") {
                        name
                    } else {
                        "$newNamespace.$name"
                    }
                }

                Schema.Type.ARRAY.getName() -> {
                    val itemType = json["items"]
                    collectSchemaImportTypes(itemType, namespace, schemas, declaredTypes)
                }

                Schema.Type.MAP.getName() -> {
                    val itemType = json["values"]
                    collectSchemaImportTypes(itemType, namespace, schemas, declaredTypes)
                }

                Schema.Type.RECORD.getName() -> {
                    val fields = json["fields"]
                    if (!fields.isArray) throw java.lang.IllegalArgumentException("Expected fields array")
                    val name = json["name"].textValue()
                    val newNamespace = if (json.has("namespace")) {
                        json["namespace"].textValue()
                    } else {
                        namespace
                    }
                    declaredTypes += if (name.contains(".") || newNamespace == "") {
                        name
                    } else {
                        "$newNamespace.$name"
                    }
                    for (field in fields.elements()) {
                        collectSchemaImportTypes(field, newNamespace, schemas, declaredTypes)
                    }
                }

                else -> {
                    schemas += if (typeString.contains(".") || namespace == "") {
                        typeString
                    } else {
                        "$namespace.$typeString"
                    }
                }
            }
        }
    } else if (json.isTextual) {
        when (val typeString = json.textValue()) {
            Schema.Type.NULL.getName(),
            Schema.Type.BOOLEAN.getName(),
            Schema.Type.INT.getName(),
            Schema.Type.LONG.getName(),
            Schema.Type.BYTES.getName(),
            Schema.Type.STRING.getName(),
            Schema.Type.FIXED.getName(),
            Schema.Type.FLOAT.getName(),
            Schema.Type.DOUBLE.getName(),
            -> {
                // ignore
            }

            Schema.Type.ENUM.getName(),
            Schema.Type.MAP.getName(),
            Schema.Type.ARRAY.getName(),
            Schema.Type.RECORD.getName() -> {
                throw java.lang.IllegalArgumentException("Cannot use compound types as primitive")
            }

            else -> {
                schemas += if (typeString.contains(".") || namespace == "") {
                    typeString
                } else {
                    "$namespace.$typeString"
                }
            }
        }
    } else {
        throw java.lang.IllegalArgumentException("Unexpected json node type $json")
    }
}

fun resolveSchemas(schemas: Iterable<String>): Map<String, Schema> {
    val unprocessed = schemas.toMutableList()
    val types = LinkedHashMap<String, Schema>()
    val om = ObjectMapper()
    var lastError: Exception? = null
    var lastSchema: String? = null
    while (unprocessed.isNotEmpty()) {
        var progress = false
        val iter = unprocessed.listIterator()
        while (iter.hasNext()) {
            val newSchema = iter.next()
            lastSchema = newSchema
            try {
                val json = om.readTree(newSchema)
                val requiredSchemas = collectSchemaImportTypes(json)
                val parser = Schema.Parser()
                for (type in requiredSchemas) {
                    val knownSchema = types[type]
                    if (knownSchema != null) {
                        parser.addTypes(mapOf(type to knownSchema))
                    } else {
                        val knownAlias = types.values.firstOrNull { it.aliases.contains(type) }
                        if (knownAlias != null) {
                            parser.addTypes(mapOf(knownAlias.fullName to knownAlias))
                        } else {
                            throw AvroTypeException("Unknown schema type $type")
                        }
                    }
                }
                parser.parse(newSchema)
                for (typePair in parser.types) {
                    if (!types.containsKey(typePair.key)) {
                        val hash =
                            SchemaNormalization.parsingFingerprint(SchemaRegistry.FingerprintHash, typePair.value)
                        val sig = SchemaRegistry.FingerprintAliasPrefix + hash.printHexBinary()
                        typePair.value.addAlias(sig)
                        types[typePair.key] = typePair.value
                    }
                }
                iter.remove()
                progress = true
            } catch (ex: Exception) {
                lastError = ex
            }
        }
        if (!progress) {
            throw IllegalArgumentException("Unable to resolve schemas $lastSchema ", lastError)
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

fun GenericRecord.serializeJSON(): String {
    val datumWriter = GenericDatumWriter<GenericRecord>(schema)
    val byteStream = ByteArrayOutputStream()
    byteStream.use {
        val jsonEncoder = EncoderFactory().jsonEncoder(schema, it, false)
        datumWriter.write(this, jsonEncoder)
        jsonEncoder.flush()
        byteStream.flush()
        return String(byteStream.toByteArray(), Charsets.UTF_8)
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

fun GenericRecord.clone(): GenericRecord {
    return schema.deserialize(serialize())
}

typealias AvroEncoder<T> = (T) -> GenericRecord
typealias AvroDecoder<T> = (GenericRecord) -> T

data class AvroCodec<T>(val enc: AvroEncoder<T>, val dec: AvroDecoder<T>)

object AvroTypeHelpers {
    val helpers = mutableMapOf<Class<*>, AvroCodec<*>>()

    fun <T> registerHelper(clazz: Class<T>, encoder: AvroEncoder<T>, decoder: AvroDecoder<T>) {
        helpers[clazz] = AvroCodec(encoder, decoder)
    }
}

private fun deserializeInternal(
    bytes: ByteArray,
    datumReader: GenericDatumReader<GenericRecord>
): GenericRecord {
    return try {
        val decoder = DecoderFactory.get().binaryDecoder(bytes, null)
        val data = datumReader.read(null, decoder)
        if (!decoder.isEnd) {
            throw IOException()
        }
        data
    } catch (io: IOException) {
        throw io
    } catch (ex: Exception) {
        throw IOException("Invalid length", ex)
    }
}

fun Schema.deserialize(bytes: ByteArray): GenericRecord {
    val datumReader = GenericDatumReader<GenericRecord>(this)
    return deserializeInternal(bytes, datumReader)
}

fun Schema.deserializeArray(bytes: ByteArray): GenericArray<GenericRecord> {
    val datumReader = GenericDatumReader<GenericArray<GenericRecord>>(this)
    return try {
        val decoder = DecoderFactory.get().binaryDecoder(bytes, null)
        val data = datumReader.read(null, decoder)
        if (!decoder.isEnd) {
            throw IOException()
        }
        data
    } catch (io: IOException) {
        throw io
    } catch (ex: Exception) {
        throw IOException("Invalid length", ex)
    }
}

fun Schema.deserialize(bytes: ByteArray, oldSchema: Schema): GenericRecord {
    val datumReader = GenericDatumReader<GenericRecord>(oldSchema, this)
    return deserializeInternal(bytes, datumReader)
}

fun Schema.deserializeJSON(json: String): GenericRecord {
    val datumReader = GenericDatumReader<GenericRecord>(this)
    val jsonDecoder = DecoderFactory().jsonDecoder(this, json)
    return datumReader.read(null, jsonDecoder)
}

inline fun <reified T : Enum<T>> GenericRecord.getTypedEnum(fieldName: String): T {
    val value = this.get(fieldName) ?: return null as T
    val enumString = (value as GenericEnumSymbol<*>).toString()
    return enumValueOf<T>(enumString)
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T> GenericRecord.getTyped(fieldName: String): T {
    val value = this.get(fieldName) ?: return null as T
    val clazz = T::class.java
    val pluginHandlers = AvroTypeHelpers.helpers[clazz]
    if (pluginHandlers != null) {
        return pluginHandlers.dec(value as GenericRecord) as T
    }
    if (AvroConvertible::class.java.isAssignableFrom(clazz)) {
        if (this.schema.getField(fieldName)
                .schema().isUnion
        ) { // assume union base is AvroConvertible to avoid simple nullable unions
            val unionSchema = (value as GenericRecord).schema
            val unionClazz = clazz.classLoader.loadClass(unionSchema.fullName) // require named matches class name
            val unionPluginHandler = AvroTypeHelpers.helpers[unionClazz]
            if (unionPluginHandler != null) {
                return getTyped(fieldName) { record -> unionPluginHandler.dec(record) as T }
            }
            val unionConstructor = unionClazz.getConstructor(GenericRecord::class.java)
            return getTyped(fieldName) { record -> unionConstructor.newInstance(record) as T }
        }
        val constructor = clazz.getConstructor(GenericRecord::class.java)
        return constructor.newInstance(value)
    }
    if (clazz.isEnum) {
        throw IllegalArgumentException("Use getTypedEnum for enums")
    }
    return when (clazz) {
        String::class.java -> value.toString()
        ByteArray::class.java -> getBytes(fieldName, value)
        BigDecimal::class.java -> getDecimal(fieldName)
        UUID::class.java -> getUUID(fieldName)
        Instant::class.java -> getInstant(fieldName)
        LocalDate::class.java -> getLocalDate(fieldName)
        LocalTime::class.java -> getLocalTime(fieldName)
        LocalDateTime::class.java -> getLocalDateTime(fieldName)
        Map::class.java -> getMap(fieldName, value as Map<CharSequence, *>)
        else -> value
    } as T
}

fun GenericRecord.getBytes(fieldName: String, value: Any): ByteArray {
    val fieldSchema = schema.getField(fieldName).schema()
    return if (fieldSchema.type == Schema.Type.FIXED) {
        (value as GenericData.Fixed).bytes().copyOf()
    } else {
        (value as ByteBuffer).array().copyOf()
    }
}

fun GenericRecord.getDecimal(fieldName: String): BigDecimal {
    val fieldSchema = schema.getField(fieldName).schema()
    return if (fieldSchema.type == Schema.Type.BYTES) {
        Conversions.DecimalConversion().fromBytes(
            get(fieldName) as ByteBuffer,
            fieldSchema,
            fieldSchema.logicalType
        )
    } else if (fieldSchema.type == Schema.Type.FIXED) {
        Conversions.DecimalConversion().fromFixed(
            get(fieldName) as GenericFixed,
            fieldSchema,
            fieldSchema.logicalType
        )
    } else {
        throw IllegalArgumentException("Invalid decimal field type")
    }
}

fun GenericRecord.getUUID(fieldName: String): UUID {
    val fieldSchema = schema.getField(fieldName).schema()
    return Conversions.UUIDConversion().fromCharSequence(
        get(fieldName) as CharSequence,
        fieldSchema,
        fieldSchema.logicalType
    )
}

fun GenericRecord.getInstant(fieldName: String): Instant {
    val fieldSchema = schema.getField(fieldName).schema()
    return if (fieldSchema.logicalType != null) {
        when (fieldSchema.logicalType.name) {
            "date" -> {
                LocalDate.ofEpochDay((get(fieldName) as Int).toLong()).atStartOfDay().toInstant(ZoneOffset.UTC)
            }

            "timestamp-millis" -> {
                Instant.ofEpochMilli(get(fieldName) as Long)
            }

            "timestamp-micros" -> {
                val micros = get(fieldName) as Long
                Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L))
            }

            else -> {
                Instant.ofEpochMilli(get(fieldName) as Long)
            }
        }
    } else {
        Instant.ofEpochMilli(get(fieldName) as Long)
    }
}

fun GenericRecord.getLocalDate(fieldName: String): LocalDate {
    val fieldSchema = schema.getField(fieldName).schema()
    return if (fieldSchema.logicalType != null) {
        when (fieldSchema.logicalType.name) {
            "date" -> {
                LocalDate.ofEpochDay((get(fieldName) as Int).toLong())
            }

            "timestamp-millis" -> {
                val instant = Instant.ofEpochMilli(get(fieldName) as Long)
                LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate()
            }

            "timestamp-micros" -> {
                val micros = get(fieldName) as Long
                val instant = Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L))
                LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate()
            }

            "local-timestamp-millis" -> {
                val instant = Instant.ofEpochMilli(get(fieldName) as Long)
                LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate()
            }

            "local-timestamp-micros" -> {
                val micros = get(fieldName) as Long
                val instant = Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L))
                LocalDateTime.ofInstant(instant, ZoneOffset.UTC).toLocalDate()
            }

            else -> {
                LocalDate.ofEpochDay((get(fieldName) as Int).toLong())
            }
        }
    } else {
        LocalDate.ofEpochDay((get(fieldName) as Int).toLong())
    }
}

fun GenericRecord.getLocalTime(fieldName: String): LocalTime {
    val fieldSchema = schema.getField(fieldName).schema()
    return if (fieldSchema.logicalType != null) {
        when (fieldSchema.logicalType.name) {
            "time-millis" -> {
                LocalTime.ofNanoOfDay((get(fieldName) as Int).toLong() * 1000000L)
            }

            "time-micros" -> {
                LocalTime.ofNanoOfDay((get(fieldName) as Long) * 1000L)
            }

            else -> {
                LocalTime.ofNanoOfDay((get(fieldName) as Int).toLong() * 1000000L)
            }
        }
    } else {
        LocalTime.ofNanoOfDay((get(fieldName) as Int).toLong() * 1000000L)
    }
}

fun GenericRecord.getLocalDateTime(fieldName: String): LocalDateTime {
    val fieldSchema = schema.getField(fieldName).schema()
    return if (fieldSchema.logicalType != null) {
        when (fieldSchema.logicalType.name) {
            "date" -> {
                LocalDate.ofEpochDay((get(fieldName) as Int).toLong()).atStartOfDay()
            }

            "timestamp-millis" -> {
                LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC)
            }

            "timestamp-micros" -> {
                val micros = get(fieldName) as Long
                LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L)),
                    ZoneOffset.UTC
                )
            }

            "local-timestamp-millis" -> {
                LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC)
            }

            "local-timestamp-micros" -> {
                val micros = get(fieldName) as Long
                LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(micros / 1000L).plusNanos(1000L * (micros % 1000L)),
                    ZoneOffset.UTC
                )
            }

            else -> {
                LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC)
            }
        }
    } else {
        LocalDateTime.ofInstant(Instant.ofEpochMilli(get(fieldName) as Long), ZoneOffset.UTC)
    }
}

fun GenericRecord.getMap(fieldName: String, value: Map<CharSequence, *>): Map<String, Any?> {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.MAP) {
        "Not a MAP type field"
    }
    if (fieldSchema.valueType.type == Schema.Type.STRING) {
        val returnValue = mutableMapOf<String, String>()
        for (kvp in value) {
            returnValue[kvp.key.toString()] = kvp.value.toString()
        }
        return returnValue
    }
    return value.mapKeys { it.key.toString() }
}

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
inline fun <reified T : Any> GenericRecord.getObjectArray(
    fieldName: String,
    constructor: (GenericRecord) -> T
): List<T> {
    return (get(fieldName) as GenericArray<GenericRecord>).map { constructor(it) }
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T : Any> GenericRecord.getObjectArrayIndexed(
    fieldName: String,
    constructor: (Int, GenericRecord) -> T
): List<T> {
    return (get(fieldName) as GenericArray<GenericRecord>).mapIndexed { index, record ->
        constructor(index, record)
    }
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.getIntArray(fieldName: String): List<Int> {
    val arrayData = get(fieldName) as GenericData.Array<Int>
    return arrayData.toList()
}

@Suppress("UNCHECKED_CAST")
inline fun <reified T : Enum<T>> GenericRecord.getEnumArray(fieldName: String): List<T> {
    val arrayData = get(fieldName) as GenericData.Array<GenericEnumSymbol<*>>
    return arrayData.map { enumValueOf<T>(it.toString()) }
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.getStringArray(fieldName: String): List<String> {
    val arrayData = get(fieldName) as GenericData.Array<Utf8>
    return arrayData.map { it.toString() }
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.getByteArrayArray(fieldName: String): List<ByteArray> {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.ARRAY) { "Not an array field" }
    val elementSchema = fieldSchema.elementType
    return if (elementSchema.type == Schema.Type.FIXED) {
        val arrayData = get(fieldName) as GenericData.Array<GenericData.Fixed>
        arrayData.map {
            it.bytes().copyOf()
        }
    } else {
        val arrayData = get(fieldName) as GenericData.Array<ByteBuffer>
        arrayData.map {
            it.array().copyOf()
        }
    }
}


@Suppress("UNCHECKED_CAST")
fun GenericRecord.putTyped(fieldName: String, value: Any?, clazz: Class<*>) {
    if (value == null) {
        put(fieldName, null)
        return
    }
    if (value is AvroConvertible) {
        put(fieldName, value.toGenericRecord())
        return
    }
    val pluginHandlers = AvroTypeHelpers.helpers[clazz]
    if (pluginHandlers != null) {
        val encoder = pluginHandlers.enc as AvroEncoder<Any?>
        put(fieldName, encoder(value))
        return
    }
    if (clazz.isEnum) {
        putEnum(fieldName, value as Enum<*>)
        return
    }
    when (clazz) {
        String::class.java -> put(fieldName, Utf8(value as String))
        ByteArray::class.java -> putBytes(fieldName, value as ByteArray)
        BigDecimal::class.java -> putDecimal(fieldName, value as BigDecimal)
        UUID::class.java -> putUUID(fieldName, value as UUID)
        Instant::class.java -> putInstant(fieldName, value as Instant)
        LocalDate::class.java -> putLocalDate(fieldName, value as LocalDate)
        LocalTime::class.java -> putLocalTime(fieldName, value as LocalTime)
        LocalDateTime::class.java -> putLocalDateTime(fieldName, value as LocalDateTime)
        else -> put(fieldName, value)
    }
}

inline fun <reified T> GenericRecord.putTyped(fieldName: String, value: T) {
    if (value == null) {
        put(fieldName, null)
        return
    }
    val clazz = T::class.java
    putTyped(fieldName, value, clazz)
}

fun GenericRecord.putEnum(fieldName: String, value: Enum<*>) {
    val fieldSchema = schema.getField(fieldName).schema()
    val enumRecord = GenericData.EnumSymbol(fieldSchema, value)
    put(fieldName, enumRecord)
}

fun GenericRecord.putBytes(fieldName: String, bytes: ByteArray) {
    val fieldSchema = schema.getField(fieldName).schema()
    if (fieldSchema.type == Schema.Type.FIXED) {
        require(bytes.size == fieldSchema.fixedSize) { "Fixed field requires input of size ${fieldSchema.fixedSize} not ${bytes.size}" }
        put(fieldName, GenericData.Fixed(fieldSchema, bytes))
    } else {
        val buffer = ByteBuffer.wrap(bytes)
        put(fieldName, buffer)
    }
}

fun GenericRecord.putDecimal(fieldName: String, decimal: BigDecimal) {
    val fieldSchema = schema.getField(fieldName).schema()
    if (fieldSchema.type == Schema.Type.BYTES) {
        val bytes = Conversions.DecimalConversion().toBytes(decimal, fieldSchema, fieldSchema.logicalType)
        put(fieldName, bytes)
    } else if (fieldSchema.type == Schema.Type.FIXED) {
        val fixed = Conversions.DecimalConversion().toFixed(decimal, fieldSchema, fieldSchema.logicalType)
        put(fieldName, fixed)
    } else {
        throw IllegalArgumentException("Invalid decimal field type")
    }
}

fun GenericRecord.putUUID(fieldName: String, uuid: UUID) {
    val fieldSchema = schema.getField(fieldName).schema()
    val uuidString = Conversions.UUIDConversion().toCharSequence(uuid, fieldSchema, fieldSchema.logicalType)
    put(fieldName, uuidString)
}

fun GenericRecord.putInstant(fieldName: String, instant: Instant) {
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

            "local-timestamp-millis" -> {
                put(fieldName, instant.toEpochMilli())
            }

            "local-timestamp-micros" -> {
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

fun GenericRecord.putLocalDate(fieldName: String, date: LocalDate) {
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

            "local-timestamp-millis" -> {
                put(fieldName, date.toEpochDay() * 86400000L)
            }

            "local-timestamp-micros" -> {
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

fun GenericRecord.putLocalTime(fieldName: String, time: LocalTime) {
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

fun GenericRecord.putLocalDateTime(fieldName: String, dateTime: LocalDateTime) {
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

            "local-timestamp-millis" -> {
                put(fieldName, dateTime.toInstant(ZoneOffset.UTC).toEpochMilli())
            }

            "local-timestamp-micros" -> {
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

fun GenericRecord.putGenericArray(fieldName: String, value: List<GenericRecord>) {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.ARRAY) { "putGenericArray only works on Array fields" }
    when (fieldSchema.elementType.type) {
        Schema.Type.RECORD -> {
            val arrayData = GenericData.Array(fieldSchema, value.map { it })
            put(fieldName, arrayData)
        }

        Schema.Type.BYTES -> {
            val arrayData = GenericData.Array(fieldSchema, value.map { ByteBuffer.wrap(it.serialize()) })
            put(fieldName, arrayData)
        }

        else -> throw IllegalArgumentException("putGenericArray only applies to Array<GenericRecord> and Array<ByteBuffer> fields")
    }
}

inline fun <reified T : AvroConvertible> GenericRecord.putObjectArray(fieldName: String, value: List<T>) {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.ARRAY) { "putObjectArray only works on Array fields" }
    when (fieldSchema.elementType.type) {
        Schema.Type.RECORD -> {
            val arrayData = GenericData.Array(fieldSchema, value.map { it.toGenericRecord() })
            put(fieldName, arrayData)
        }

        Schema.Type.BYTES -> {
            val arrayData = GenericData.Array(fieldSchema, value.map { ByteBuffer.wrap(it.serialize()) })
            put(fieldName, arrayData)
        }

        else -> throw IllegalArgumentException("putObjectArray only applies to Array<GenericRecord> and Array<ByteBuffer> fields")
    }
}

fun GenericRecord.putIntArray(fieldName: String, value: List<Int>) {
    val arrayRecord = GenericData.Array(schema.getField(fieldName).schema(), value)
    put(fieldName, arrayRecord)
}

fun <T : Enum<*>> GenericRecord.putEnumArray(fieldName: String, values: List<T>) {
    val fieldSchema = schema.getField(fieldName).schema()
    val itemSchema = fieldSchema.elementType
    val enumValues = values.map { GenericData.EnumSymbol(itemSchema, it) }
    val arrayRecord = GenericData.Array(fieldSchema, enumValues)
    put(fieldName, arrayRecord)
}

fun GenericRecord.putStringArray(fieldName: String, value: List<String>) {
    val arrayRecord = GenericData.Array(schema.getField(fieldName).schema(), value)
    put(fieldName, arrayRecord)
}

fun GenericRecord.putByteArrayArray(fieldName: String, value: List<ByteArray>) {
    val fieldSchema = schema.getField(fieldName).schema()
    require(fieldSchema.type == Schema.Type.ARRAY) { "Not an array field" }
    val elementSchema = fieldSchema.elementType
    if (elementSchema.type == Schema.Type.FIXED) {
        require(value.all { it.size == elementSchema.fixedSize }) { "Fixed field requires each element of size ${fieldSchema.fixedSize}" }
        val arrayRecord = GenericData.Array(fieldSchema, value.map { GenericData.Fixed(elementSchema, it) })
        put(fieldName, arrayRecord)
    } else {
        val arrayRecord = GenericData.Array(fieldSchema, value.map { ByteBuffer.wrap(it) })
        put(fieldName, arrayRecord)
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
    LOCAL_TIMESTAMP_MILLIS,
    LOCAL_TIMESTAMP_MICROS,
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

            "local-timestamp-millis" -> {
                return AvroExtendedType.LOCAL_TIMESTAMP_MILLIS
            }

            "local-timestamp-micros" -> {
                return AvroExtendedType.LOCAL_TIMESTAMP_MICROS
            }
            // Note duration is also defined in the specification, but java avro library currently has no support for it
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