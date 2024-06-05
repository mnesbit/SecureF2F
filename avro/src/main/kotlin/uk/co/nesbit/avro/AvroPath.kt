package uk.co.nesbit.avro

import org.apache.avro.AvroRuntimeException
import org.apache.avro.Conversions
import org.apache.avro.Schema
import org.apache.avro.generic.*
import org.apache.avro.util.Utf8
import java.math.BigDecimal
import java.nio.ByteBuffer
import java.time.*
import java.util.*

enum class ComponentType {
    FIELD,
    INDEX,
    KEY
}

data class PathComponent(val part: String, val type: ComponentType)

@Suppress("UNCHECKED_CAST")
fun GenericRecord.visit(body: (obj: Any?, schema: Schema, path: List<PathComponent>, root: GenericRecord) -> Unit) {
    data class Tracker(val obj: Any?, val schema: Schema, val path: List<PathComponent>)

    val callStack = Stack<Tracker>()
    val stack = Stack<Tracker>()
    stack.push(Tracker(this, schema, emptyList()))
    val generic = GenericData()
    while (!stack.empty()) {
        val current = stack.pop()
        when (current.schema.type) {
            Schema.Type.RECORD -> {
                callStack.push(Tracker(current.obj, current.schema, current.path))
                val record = current.obj as GenericRecord
                for (field in current.schema.fields) {
                    val value = record.get(field.name())
                    val path = current.path + PathComponent(field.name(), ComponentType.FIELD)
                    val props = field.objectProps
                    // Clone schema and push down field level properties into the field schema, so we show them to the processor
                    val schema = Schema.Parser().parse(field.schema().toString())
                    for (prop in props) {
                        if (!schema.objectProps.containsKey(prop.key)) {
                            schema.addProp(prop.key, prop.value)
                        }
                    }
                    val type = schema.type
                    if (type in setOf(Schema.Type.RECORD, Schema.Type.ARRAY, Schema.Type.MAP, Schema.Type.UNION)) {
                        stack.push(Tracker(value, schema, path))
                    } else {
                        callStack.push(Tracker(value, schema, path))
                    }
                }
            }
            Schema.Type.ARRAY -> {
                callStack.push(Tracker(current.obj, current.schema, current.path))
                val array = current.obj as GenericArray<*>
                val schema = array.schema.elementType
                val type = schema.type
                for (index in (0 until array.size).reversed()) {
                    val value = array[index]
                    val path = current.path + PathComponent(index.toString(), ComponentType.INDEX)
                    if (type in setOf(Schema.Type.RECORD, Schema.Type.ARRAY, Schema.Type.MAP, Schema.Type.UNION)) {
                        stack.push(Tracker(value, schema, path))
                    } else {
                        callStack.push(Tracker(value, schema, path))
                    }
                }
            }
            Schema.Type.MAP -> {
                val map = current.obj as Map<CharSequence, *>
                val stringKeyedMap = map.mapKeys { it.key.toString() }
                callStack.push(Tracker(stringKeyedMap, current.schema, current.path))
                val schema = current.schema.valueType
                val type = schema.type
                for (entry in map) {
                    val value = entry.value
                    val path = current.path + PathComponent(entry.key.toString(), ComponentType.KEY)
                    if (type in setOf(Schema.Type.RECORD, Schema.Type.ARRAY, Schema.Type.MAP, Schema.Type.UNION)) {
                        stack.push(Tracker(value, schema, path))
                    } else {
                        callStack.push(Tracker(value, schema, path))
                    }
                }
            }
            Schema.Type.UNION -> {
                val schemaIndexUsed = generic.resolveUnion(current.schema, current.obj)
                // Clone specific union schema and push down the original properties, so we show them to the processor
                val schema = Schema.Parser().parse(current.schema.types[schemaIndexUsed].toString())
                for (prop in current.schema.objectProps) {
                    if (!schema.objectProps.containsKey(prop.key)) {
                        schema.addProp(prop.key, prop.value)
                    }
                }
                val type = schema.type
                if (type in setOf(Schema.Type.RECORD, Schema.Type.ARRAY, Schema.Type.MAP, Schema.Type.UNION)) {
                    stack.push(Tracker(current.obj, schema, current.path))
                } else {
                    callStack.push(Tracker(current.obj, schema, current.path))
                }
            }
            else -> throw IllegalArgumentException("Require a container Schema type")
        }
    }
    while (!callStack.isEmpty()) {
        val next = callStack.pop()
        when {
            next.schema.type == Schema.Type.BYTES -> body(
                (next.obj as ByteBuffer).array(),
                next.schema,
                next.path,
                this
            )
            next.schema.type == Schema.Type.FIXED -> body(
                (next.obj as GenericFixed).bytes(),
                next.schema,
                next.path,
                this
            )
            else -> body(next.obj, next.schema, next.path, this)
        }
    }
}

interface AvroVisitor {
    fun recordVisitor(value: GenericRecord, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun enumVisitor(value: GenericEnumSymbol<*>, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun arrayVisitor(value: GenericArray<*>, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun mapVisitor(value: Map<String, Any?>, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun stringVisitor(value: String, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun bytesVisitor(value: ByteArray, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun intVisitor(value: Int, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun longVisitor(value: Long, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun floatVisitor(value: Float, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun doubleVisitor(value: Double, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun booleanVisitor(value: Boolean, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun nullVisitor(schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun decimalVisitor(value: BigDecimal, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun uuidVisitor(value: UUID, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun dateVisitor(value: LocalDate, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun timeVisitor(value: LocalTime, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun timestampVisitor(value: Instant, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun localDateTimeVisitor(value: LocalDateTime, schema: Schema, path: List<PathComponent>, root: GenericRecord)
    fun unknownVisitor(value: Any?, schema: Schema, path: List<PathComponent>, root: GenericRecord)
}

fun convertLogicalTypes(
    obj: Any?,
    schema: Schema
): Any? {
    val extendedType = schema.getExtendedType()
    return when (extendedType) {
        AvroExtendedType.UNION -> {
            throw IllegalStateException("Unions should have been resolved")
        }
        AvroExtendedType.STRING -> {
            (obj as CharSequence).toString()
        }
        AvroExtendedType.DECIMAL -> {
            Conversions.DecimalConversion()
                .fromBytes(ByteBuffer.wrap(obj as ByteArray), schema, schema.logicalType)
        }
        AvroExtendedType.UUID -> {
            Conversions.UUIDConversion().fromCharSequence(obj as CharSequence, schema, schema.logicalType)
        }
        AvroExtendedType.DATE -> {
            val days = (obj as Int).toLong()
            LocalDate.ofEpochDay(days)
        }
        AvroExtendedType.TIME_MILLIS -> {
            val millis = (obj as Int).toLong()
            LocalTime.ofNanoOfDay(millis * 1000000L)
        }
        AvroExtendedType.TIME_MICROS -> {
            val micros = (obj as Long)
            LocalTime.ofNanoOfDay(micros * 1000L)
        }
        AvroExtendedType.TIMESTAMP_MILLIS -> {
            val millis = (obj as Long)
            Instant.ofEpochMilli(millis)
        }
        AvroExtendedType.TIMESTAMP_MICROS -> {
            val micros = (obj as Long)
            val millis = micros / 1000L
            val extraNanos = (micros - (1000L * millis)) * 1000L
            Instant.ofEpochMilli(millis).plusNanos(extraNanos)
        }
        AvroExtendedType.LOCAL_TIMESTAMP_MILLIS -> {
            val millis = (obj as Long)
            val instant = Instant.ofEpochMilli(millis)
            LocalDateTime.ofInstant(instant, ZoneOffset.UTC)
        }

        AvroExtendedType.LOCAL_TIMESTAMP_MICROS -> {
            val micros = (obj as Long)
            val millis = micros / 1000L
            val extraNanos = (micros - (1000L * millis)) * 1000L
            val instant = Instant.ofEpochMilli(millis).plusNanos(extraNanos)
            LocalDateTime.ofInstant(instant, ZoneOffset.UTC)
        }
        else -> {
            obj
        }
    }
}

fun GenericRecord.visitWithLogicalTypes(body: (obj: Any?, schema: Schema, path: List<PathComponent>, root: GenericRecord) -> Unit) {
    visit { obj, schema, path, root ->
        val objOut = convertLogicalTypes(obj, schema)
        body(objOut, schema, path, root)
    }
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.visit(visitor: AvroVisitor) {
    visit { obj, schema, path, root ->
        val extendedType = schema.getExtendedType()
        when (extendedType) {
            AvroExtendedType.RECORD -> {
                visitor.recordVisitor(obj as GenericRecord, schema, path, root)
            }
            AvroExtendedType.ENUM -> {
                visitor.enumVisitor(obj as GenericEnumSymbol<*>, schema, path, root)
            }
            AvroExtendedType.ARRAY -> {
                visitor.arrayVisitor(obj as GenericArray<*>, schema, path, root)
            }
            AvroExtendedType.MAP -> {
                visitor.mapVisitor(obj as Map<String, Any?>, schema, path, root)
            }
            AvroExtendedType.UNION -> {
                throw IllegalStateException("Unions should have been resolved")
            }
            AvroExtendedType.FIXED -> {
                // We should have already resolved Fixed to ByteArray
                visitor.bytesVisitor(obj as ByteArray, schema, path, root)
            }
            AvroExtendedType.STRING -> {
                visitor.stringVisitor((obj as CharSequence).toString(), schema, path, root)
            }
            AvroExtendedType.BYTES -> {
                visitor.bytesVisitor(obj as ByteArray, schema, path, root)
            }
            AvroExtendedType.INT -> {
                visitor.intVisitor(obj as Int, schema, path, root)
            }
            AvroExtendedType.LONG -> {
                visitor.longVisitor(obj as Long, schema, path, root)
            }
            AvroExtendedType.FLOAT -> {
                visitor.floatVisitor(obj as Float, schema, path, root)
            }
            AvroExtendedType.DOUBLE -> {
                visitor.doubleVisitor(obj as Double, schema, path, root)
            }
            AvroExtendedType.BOOLEAN -> {
                visitor.booleanVisitor(obj as Boolean, schema, path, root)
            }
            AvroExtendedType.NULL -> {
                visitor.nullVisitor(schema, path, root)
            }
            AvroExtendedType.DECIMAL -> {
                val decimalValue = Conversions.DecimalConversion()
                    .fromBytes(ByteBuffer.wrap(obj as ByteArray), schema, schema.logicalType)
                visitor.decimalVisitor(decimalValue, schema, path, root)
            }
            AvroExtendedType.UUID -> {
                val uuidValue =
                    Conversions.UUIDConversion().fromCharSequence(obj as CharSequence, schema, schema.logicalType)
                visitor.uuidVisitor(uuidValue, schema, path, root)
            }
            AvroExtendedType.DATE -> {
                val days = (obj as Int).toLong()
                val date = LocalDate.ofEpochDay(days)
                visitor.dateVisitor(date, schema, path, root)
            }
            AvroExtendedType.TIME_MILLIS -> {
                val millis = (obj as Int).toLong()
                val time = LocalTime.ofNanoOfDay(millis * 1000000L)
                visitor.timeVisitor(time, schema, path, root)
            }
            AvroExtendedType.TIME_MICROS -> {
                val micros = (obj as Long)
                val time = LocalTime.ofNanoOfDay(micros * 1000L)
                visitor.timeVisitor(time, schema, path, root)
            }
            AvroExtendedType.TIMESTAMP_MILLIS -> {
                val millis = (obj as Long)
                val instant = Instant.ofEpochMilli(millis)
                visitor.timestampVisitor(instant, schema, path, root)
            }
            AvroExtendedType.TIMESTAMP_MICROS -> {
                val micros = (obj as Long)
                val millis = micros / 1000L
                val extraNanos = (micros - (1000L * millis)) * 1000L
                val instant = Instant.ofEpochMilli(millis).plusNanos(extraNanos)
                visitor.timestampVisitor(instant, schema, path, root)
            }
            AvroExtendedType.LOCAL_TIMESTAMP_MILLIS -> {
                val millis = (obj as Long)
                val instant = Instant.ofEpochMilli(millis)
                val localDateTime = LocalDateTime.ofInstant(instant, ZoneOffset.UTC)
                visitor.localDateTimeVisitor(localDateTime, schema, path, root)
            }

            AvroExtendedType.LOCAL_TIMESTAMP_MICROS -> {
                val micros = (obj as Long)
                val millis = micros / 1000L
                val extraNanos = (micros - (1000L * millis)) * 1000L
                val instant = Instant.ofEpochMilli(millis).plusNanos(extraNanos)
                val localDateTime = LocalDateTime.ofInstant(instant, ZoneOffset.UTC)
                visitor.localDateTimeVisitor(localDateTime, schema, path, root)
            }
            AvroExtendedType.UNKNOWN -> {
                visitor.unknownVisitor(obj, schema, path, root)
            }
        }
    }
}

fun splitStringPath(path: String): List<PathComponent> {
    val pathComponents = mutableListOf<PathComponent>()
    var componentStartIndex = 0
    var componentEndIndex = 0
    while (componentEndIndex < path.length) {
        val ch = path[componentEndIndex]
        if (ch == '.') {
            pathComponents.add(
                PathComponent(
                    path.substring(componentStartIndex, componentEndIndex),
                    ComponentType.FIELD
                )
            )
            componentStartIndex = componentEndIndex + 1
            componentEndIndex = componentStartIndex
        } else if (ch == '[') {
            if (componentStartIndex < componentEndIndex) {
                pathComponents.add(
                    PathComponent(
                        path.substring(componentStartIndex, componentEndIndex),
                        ComponentType.FIELD
                    )
                )
            }
            ++componentEndIndex
            if (path[componentEndIndex] == '"') {
                componentStartIndex = componentEndIndex + 1
                componentEndIndex = componentStartIndex
                while (componentEndIndex < path.length) {
                    val chInner = path[componentEndIndex]
                    if (chInner == '"') {
                        pathComponents.add(
                            PathComponent(
                                path.substring(componentStartIndex, componentEndIndex),
                                ComponentType.KEY
                            )
                        )
                        ++componentEndIndex
                        require(path[componentEndIndex] == ']') { "path component not correctly terminated" }
                        componentStartIndex = componentEndIndex + 1
                        if (componentStartIndex < path.length && path[componentStartIndex] == '.') ++componentStartIndex
                        componentEndIndex = componentStartIndex
                        break
                    } else {
                        ++componentEndIndex
                    }
                }
                require(componentStartIndex == componentEndIndex) { "path component not correctly terminated" }
            } else {
                componentStartIndex = componentEndIndex
                while (componentEndIndex < path.length) {
                    val chInner = path[componentEndIndex]
                    if (chInner == ']') {
                        pathComponents.add(
                            PathComponent(
                                path.substring(componentStartIndex, componentEndIndex),
                                ComponentType.INDEX
                            )
                        )
                        componentStartIndex = componentEndIndex + 1
                        if (componentStartIndex < path.length && path[componentStartIndex] == '.') ++componentStartIndex
                        componentEndIndex = componentStartIndex
                        break
                    } else if (chInner.isDigit()) {
                        ++componentEndIndex
                    } else throw IndexOutOfBoundsException("path index component must be numeric")
                }
                require(componentStartIndex == componentEndIndex) { "path component not correctly terminated" }
            }
        } else if (ch.isLetterOrDigit() || ch == '_') {
            ++componentEndIndex
        } else throw AvroRuntimeException("Invalid character encountered $ch")
    }
    if (componentStartIndex != componentEndIndex) {
        pathComponents.add(PathComponent(path.substring(componentStartIndex), ComponentType.FIELD))
    }
    return pathComponents
}

fun List<PathComponent>.toStringPath(): String {
    val sb = StringBuilder()
    for (component in this) {
        when (component.type) {
            ComponentType.FIELD -> {
                if (sb.isNotEmpty()) sb.append(".")
                sb.append(component.part)
            }
            ComponentType.INDEX -> {
                sb.append("[")
                sb.append(component.part)
                sb.append("]")
            }
            ComponentType.KEY -> {
                sb.append("[\"")
                sb.append(component.part)
                sb.append("\"]")
            }
        }
    }
    return sb.toString()
}

fun GenericRecord.find(path: String): Pair<Any?, Schema> {
    val pathComponents = splitStringPath(path)
    require(path == pathComponents.toStringPath()) { "path badly formatted" }
    return find(pathComponents)
}

@Suppress("UNCHECKED_CAST")
fun GenericRecord.find(path: List<PathComponent>): Pair<Any?, Schema> {
    var current: Any? = this
    var schema: Schema = this.schema
    val generic = GenericData()
    for (component in path) {
        when (component.type) {
            ComponentType.FIELD -> {
                if (schema.type != Schema.Type.RECORD) throw AvroRuntimeException("Not a record type")
                val record = current as GenericRecord
                current = record.get(component.part)
                schema = schema.getField(component.part).schema()
            }
            ComponentType.INDEX -> {
                if (schema.type != Schema.Type.ARRAY) throw AvroRuntimeException("Not an array type")
                val index = component.part.toInt()
                val array = current as GenericArray<*>
                current = array[index]
                schema = schema.elementType
            }
            ComponentType.KEY -> {
                if (schema.type != Schema.Type.MAP) throw AvroRuntimeException("Not a map type")
                val map = current as Map<CharSequence, *>
                current = map[component.part] ?: map[Utf8(component.part)]
                schema = schema.valueType
            }
        }
        if (schema.type == Schema.Type.UNION) {
            val schemaIndexUsed = generic.resolveUnion(schema, current)
            schema = schema.types[schemaIndexUsed]
        }
    }
    when {
        schema.type == Schema.Type.MAP -> current = (current as Map<CharSequence, *>).mapKeys { it.key.toString() }
        schema.type == Schema.Type.FIXED -> current = (current as GenericFixed).bytes()
        schema.type == Schema.Type.BYTES -> current = (current as ByteBuffer).array()
    }
    return Pair(current, schema)
}


@Suppress("UNCHECKED_CAST")
fun GenericRecord.set(path: List<PathComponent>, value: Any?) {
    var current: Any? = this
    var schema: Schema = this.schema
    val generic = GenericData()
    for (componentIndex in path.indices) {
        val component = path[componentIndex]
        val lastComponent = (componentIndex == path.size - 1)
        when (component.type) {
            ComponentType.FIELD -> {
                if (schema.type != Schema.Type.RECORD) throw AvroRuntimeException("Not a record type")
                val record = current as GenericRecord
                schema = schema.getField(component.part).schema()
                if (lastComponent) {
                    record.putTyped(component.part, value, value?.javaClass ?: Any::class.java)
                    return
                }
                current = record.get(component.part)
            }

            ComponentType.INDEX -> {
                if (schema.type != Schema.Type.ARRAY) throw AvroRuntimeException("Not an array type")
                val index = component.part.toInt()
                val array = current as GenericArray<Any?>
                schema = schema.elementType
                if (lastComponent) {
                    array[index] = value
                    return
                }
                current = array[index]
            }

            ComponentType.KEY -> {
                if (schema.type != Schema.Type.MAP) throw AvroRuntimeException("Not a map type")
                val map = current as MutableMap<CharSequence, Any?>
                schema = schema.valueType
                if (lastComponent) {
                    map[Utf8(component.part)] = value
                    return
                }
                current = map[component.part] ?: map[Utf8(component.part)]
            }
        }
        if (schema.type == Schema.Type.UNION) {
            val schemaIndexUsed = generic.resolveUnion(schema, current)
            schema = schema.types[schemaIndexUsed]
        }
    }
}


fun GenericRecord.findWithLogicalTypes(path: List<PathComponent>): Pair<Any?, Schema> {
    val (obj, schema) = find(path)
    val outputObj = convertLogicalTypes(obj, schema)
    return Pair(outputObj, schema)
}
