package uk.co.nesbit.avro

import org.apache.avro.AvroRuntimeException
import org.apache.avro.Schema
import org.apache.avro.generic.GenericArray
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericEnumSymbol
import org.apache.avro.generic.GenericRecord
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import uk.co.nesbit.utils.readTextAndClose
import java.math.BigDecimal
import java.time.*
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.test.assertFailsWith

class TestAvroUtils {
    private val schemaWithLogicalTypes = """
            {
                "name" : "Test",
                "type" : "record",
                "fields" : [
                    {
                        "name" : "id",
                        "type" : {
                            "type" : "string",
                            "logicalType" : "uuid"
                        }
                    },
                    {
                        "name" : "time1",
                        "type" : {
                            "type" : "long",
                            "logicalType" : "timestamp-millis"
                        }
                    },
                    {
                        "name" : "time2",
                        "type" : {
                            "type" : "long",
                            "logicalType" : "timestamp-micros"
                        }
                    },
                    {
                        "name" : "time3",
                        "type" : {
                            "type" : "int",
                            "logicalType" : "time-millis"
                        }
                    },
                    {
                        "name" : "time4",
                        "type" : {
                            "type" : "long",
                            "logicalType" : "time-micros"
                        }
                    },
                    {
                        "name" : "time5",
                        "type" : {
                            "type" : "long"
                        }
                    },
                    {
                        "name" : "date",
                        "type" : {
                            "type" : "int",
                            "logicalType" : "date"
                        }
                    },
                    {
                        "name": "amount",
                        "type": {
                            "type": "bytes",
                            "logicalType": "decimal",
                            "precision": 10,
                            "scale": 2
                        }
                    },
                    {
                        "name": "time6",
                        "type": {
                            "type":  "long",
                            "logicalType": "local-timestamp-millis"
                        }
                    },
                    {
                        "name": "time7",
                        "type": {
                            "type":  "long",
                            "logicalType": "local-timestamp-micros"
                        }
                    }
                ]
            }
"""

    @Test
    fun `Check logical type support`() {
        val testSchema = Schema.Parser().parse(schemaWithLogicalTypes)

        val record = GenericData.Record(testSchema)
        val id = UUID.randomUUID()
        val time = Clock.systemUTC().instant()
        val localDateTime = LocalDateTime.ofInstant(time, ZoneOffset.UTC)
        val date = localDateTime.toLocalDate()
        val amount = BigDecimal("12345.67")
        record.putTyped("id", id)
        record.putTyped("time1", time)
        record.putTyped("time2", time)
        record.putTyped("time3", time)
        record.putTyped("time4", time)
        record.putTyped("time5", time)
        record.putTyped("date", time)
        record.putTyped("amount", amount)
        record.putTyped("time6", time)
        record.putTyped("time7", time)
        val ser = record.serialize()
        val deser = testSchema.deserialize(ser)
        checkTimeRecords(deser, time)
        val outAmount = deser.getTyped<BigDecimal>("amount")
        val outId = deser.getTyped<UUID>("id")
        assertEquals(id, outId)
        assertEquals(amount, outAmount)

        val record2 = GenericData.Record(testSchema)
        record2.putTyped("id", id)
        record2.putTyped("time1", localDateTime)
        record2.putTyped("time2", localDateTime)
        record2.putTyped("time3", localDateTime)
        record2.putTyped("time4", localDateTime)
        record2.putTyped("time5", localDateTime)
        record2.putTyped("date", localDateTime)
        record2.putTyped("amount", amount)
        record2.putTyped("time6", localDateTime)
        record2.putTyped("time7", localDateTime)
        val ser2 = record2.serialize()
        val deser2 = testSchema.deserialize(ser2)
        checkTimeRecords(deser2, time)

        val record3 = GenericData.Record(testSchema)
        record3.putTyped("id", id)
        record3.putTyped("time1", localDateTime.toLocalDate())
        record3.putTyped("time2", localDateTime.toLocalDate())
        record3.putTyped("time3", localDateTime.toLocalTime())
        record3.putTyped("time4", localDateTime.toLocalTime())
        record3.putTyped("time5", localDateTime)
        record3.putTyped("date", date)
        record3.putTyped("amount", amount)
        record3.putTyped("time6", localDateTime)
        record3.putTyped("time7", localDateTime)
        val ser3 = record3.serialize()
        val deser3 = testSchema.deserialize(ser3)
        checkTimeRecords2(deser3, localDateTime)
        val ser4 = record3.serializeJSON()
        val deser4 = testSchema.deserializeJSON(ser4)
        kotlin.test.assertEquals(record3, deser4)
    }

    private fun checkTimeRecords(deser: GenericRecord, time: Instant) {
        val localDateTime = LocalDateTime.ofInstant(time, ZoneOffset.UTC)
        val date = localDateTime.toLocalDate()
        val outTime1 = deser.getTyped<Instant>("time1")
        val outTime2 = deser.getTyped<Instant>("time2")
        val outTime3 = deser.getTyped<Instant>("time5")
        val outTime4 = deser.getTyped<Instant>("date")
        val outTime5 = deser.getTyped<LocalTime>("time3")
        val outTime6 = deser.getTyped<LocalTime>("time4")
        val outTime7 = deser.getTyped<LocalDate>("time1")
        val outTime8 = deser.getTyped<LocalDate>("time2")
        val outTime9 = deser.getTyped<LocalDate>("date")
        val outTime10 = deser.getTyped<LocalDateTime>("time1")
        val outTime11 = deser.getTyped<LocalDateTime>("time2")
        val outTime12 = deser.getTyped<LocalDateTime>("time5")
        val outTime13 = deser.getTyped<LocalDateTime>("date")

        val outDate = deser.getTyped<LocalDate>("date")
        assertEquals(time.truncatedTo(ChronoUnit.MILLIS), outTime1)
        assertEquals(time.truncatedTo(ChronoUnit.MICROS), outTime2)
        assertEquals(time.truncatedTo(ChronoUnit.MILLIS), outTime3)
        assertEquals(time.truncatedTo(ChronoUnit.DAYS), outTime4)
        assertEquals(localDateTime.toLocalTime().truncatedTo(ChronoUnit.MILLIS), outTime5)
        assertEquals(localDateTime.toLocalTime().truncatedTo(ChronoUnit.MICROS), outTime6)
        assertEquals(localDateTime.toLocalDate(), outTime7)
        assertEquals(localDateTime.toLocalDate(), outTime8)
        assertEquals(localDateTime.toLocalDate(), outTime9)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.MILLIS), outTime10)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.MICROS), outTime11)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.MILLIS), outTime12)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.DAYS), outTime13)
        assertEquals(date, outDate)
    }

    private fun checkTimeRecords2(deser: GenericRecord, localDateTime: LocalDateTime) {
        val date = localDateTime.toLocalDate()
        val time = localDateTime.toLocalTime()
        val outTime1 = deser.getTyped<Instant>("time1")
        val outTime2 = deser.getTyped<Instant>("time2")
        val outTime3 = deser.getTyped<Instant>("time5")
        val outTime4 = deser.getTyped<Instant>("date")
        val outTime5 = deser.getTyped<LocalTime>("time3")
        val outTime6 = deser.getTyped<LocalTime>("time4")
        val outTime7 = deser.getTyped<LocalDate>("time1")
        val outTime8 = deser.getTyped<LocalDate>("time2")
        val outTime9 = deser.getTyped<LocalDate>("date")
        val outTime10 = deser.getTyped<LocalDateTime>("time1")
        val outTime11 = deser.getTyped<LocalDateTime>("time2")
        val outTime12 = deser.getTyped<LocalDateTime>("time5")
        val outTime13 = deser.getTyped<LocalDateTime>("date")

        val outDate = deser.getTyped<LocalDate>("date")
        assertEquals(date, LocalDateTime.ofInstant(outTime1, ZoneOffset.UTC).toLocalDate())
        assertEquals(date, LocalDateTime.ofInstant(outTime2, ZoneOffset.UTC).toLocalDate())
        assertEquals(
            time.truncatedTo(ChronoUnit.MILLIS),
            LocalDateTime.ofInstant(outTime3, ZoneOffset.UTC).toLocalTime()
        )
        assertEquals(date, LocalDateTime.ofInstant(outTime4, ZoneOffset.UTC).toLocalDate())
        assertEquals(localDateTime.toLocalTime().truncatedTo(ChronoUnit.MILLIS), outTime5)
        assertEquals(localDateTime.toLocalTime().truncatedTo(ChronoUnit.MICROS), outTime6)
        assertEquals(localDateTime.toLocalDate(), outTime7)
        assertEquals(localDateTime.toLocalDate(), outTime8)
        assertEquals(localDateTime.toLocalDate(), outTime9)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.DAYS), outTime10)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.DAYS), outTime11)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.MILLIS), outTime12)
        assertEquals(localDateTime.truncatedTo(ChronoUnit.DAYS), outTime13)
        assertEquals(date, outDate)
    }

    @Test
    fun `Test avro visitor utility`() {
        val sch = PathComponent::class.java.getResourceAsStream("/uk/co/nesbit/avro/complicatedSchema.avsc")!!
            .readTextAndClose()
        val complicatedSchemaWithNesting = Schema.Parser().parse(sch)
        val record = GenericData.Record(complicatedSchemaWithNesting)
        record.putTyped("stringField", "string1")
        record.putTyped("intField", 1)
        record.putTyped("longField", 2L)
        record.putTyped("binaryField", "bytes".toByteArray(Charsets.UTF_8))
        record.putTyped("floatField", 1.234f)
        record.putTyped("doubleField", 5.6789)
        record.putTyped("booleanField", true)
        record.putTyped("fixedField", "0123456789ABCDEF".toByteArray(Charsets.UTF_8))
        val enumTemp = GenericData.EnumSymbol(complicatedSchemaWithNesting.getField("enumField").schema(), "HEARTS")
        record.putTyped("enumField", enumTemp)
        val unionRecordTypeB = GenericData.Record(complicatedSchemaWithNesting.getField("unionField").schema().types[1])
        unionRecordTypeB.putTyped("b", 1)
        record.putTyped("unionField", unionRecordTypeB)
        record.putTyped("decimalField", BigDecimal.valueOf(1234567809L, 2))
        record.putTyped("uuidField", UUID.nameUUIDFromBytes("hello".toByteArray(Charsets.UTF_8)))
        record.put("nulledUnionField", null)
        val now = Clock.systemUTC().instant()
        val nowDateTime = LocalDateTime.ofInstant(now, ZoneOffset.UTC)
        record.putTyped("dateField", nowDateTime.toLocalDate())
        record.putTyped("timeMilliField", nowDateTime.toLocalTime())
        record.putTyped("timeMicroField", nowDateTime.toLocalTime())
        record.putTyped("timestampMilliField", nowDateTime)
        record.putTyped("timestampMicroField", nowDateTime)
        record.putTyped("localTimestampMilliField", nowDateTime)
        record.putTyped("localTimestampMicroField", nowDateTime)
        val simpleArrayRecord =
            GenericData.Array<Int>(complicatedSchemaWithNesting.getField("arrayField").schema(), listOf(1, 2, 3, 4))
        record.putTyped("arrayField", simpleArrayRecord)
        val simpleMap = mapOf("a" to 1, "b" to 2, "c" to 3)
        record.putTyped("mapField", simpleMap)
        val nestedRecord = GenericData.Record(complicatedSchemaWithNesting.getField("nestedRecord").schema())
        nestedRecord.putTyped("intSubField", 100)
        nestedRecord.putTyped("unionSubField", unionRecordTypeB)
        nestedRecord.putTyped("arraySubField", simpleArrayRecord)
        val simpleMap2 = mapOf("a" to "apple", "b" to "blaster", "c" to "cyberman")
        nestedRecord.putTyped("mapSubField", simpleMap2)
        record.putTyped("nestedRecord", nestedRecord)
        val nestedArray =
            GenericData.Array<GenericRecord>(2, complicatedSchemaWithNesting.getField("nestedArray").schema())
        nestedArray.add(nestedRecord)
        nestedArray.add(nestedRecord)
        record.putTyped("nestedArray", nestedArray)
        val nestedMap = mutableMapOf<String, GenericRecord>()
        nestedMap["first"] = nestedRecord
        nestedMap["second"] = nestedRecord
        record.putTyped("nestedMap", nestedMap)
        val serialized = record.serialize()
        val expected = mutableListOf<Pair<Any?, String>>()
        record.visit { obj, schema, path, root ->
            if (schema.type !in setOf(Schema.Type.RECORD, Schema.Type.ARRAY, Schema.Type.MAP)) {
                expected.add(Pair(obj, path.toStringPath()))
            }
            val refind = root.find(path)
            assertEquals(obj, refind.first)
            assertEquals(schema, refind.second)
        }
        val deserialized = complicatedSchemaWithNesting.deserialize(serialized)
        val intMap = deserialized.getTyped<Map<String, Int>>("mapField")
        assertEquals(simpleMap, intMap) // just a quick test of map logic
        var counter = 0
        deserialized.visit { obj, schema, path, root ->
            if (schema.type !in setOf(Schema.Type.RECORD, Schema.Type.ARRAY, Schema.Type.MAP)) {
                when (obj) {
                    is ByteArray -> {
                        assertEquals(expected[counter].second, path.toStringPath())
                        assertArrayEquals(expected[counter++].first as ByteArray, obj)
                    }
                    is CharSequence -> {
                        assertEquals(expected[counter].second, path.toStringPath())
                        assertEquals(expected[counter++].first.toString(), obj.toString())
                    }
                    else -> assertEquals(expected[counter++], Pair(obj, path.toStringPath()))
                }
            }
            val refind = root.find(path)
            assertEquals(obj, refind.first)
            assertEquals(schema, refind.second)
        }
        assertEquals(expected.size, counter)
        deserialized.visit(object : AvroVisitor {
            override fun recordVisitor(
                value: GenericRecord,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assert(
                    pathStr in setOf(
                        "",
                        "unionField",
                        "nestedRecord", "nestedRecord.unionSubField",
                        "nestedArray[0]", "nestedArray[0].unionSubField",
                        "nestedArray[1]", "nestedArray[1].unionSubField",
                        "nestedMap[\"first\"]", "nestedMap[\"first\"].unionSubField",
                        "nestedMap[\"second\"]", "nestedMap[\"second\"].unionSubField"
                    )
                )
            }

            override fun enumVisitor(
                value: GenericEnumSymbol<*>,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assert(
                    pathStr in setOf(
                        "enumField"
                    )
                )
                assert(value.toString() in setOf("HEARTS"))
            }

            override fun arrayVisitor(
                value: GenericArray<*>,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assert(
                    pathStr in setOf(
                        "arrayField",
                        "nestedRecord.arraySubField",
                        "nestedArray", "nestedArray[0].arraySubField", "nestedArray[1].arraySubField",
                        "nestedMap[\"first\"].arraySubField", "nestedMap[\"second\"].arraySubField"
                    )
                )
            }

            override fun mapVisitor(
                value: Map<String, Any?>,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assert(
                    pathStr in setOf(
                        "mapField",
                        "nestedRecord.mapSubField",
                        "nestedArray[0].mapSubField", "nestedArray[1].mapSubField",
                        "nestedMap", "nestedMap[\"first\"].mapSubField", "nestedMap[\"second\"].mapSubField"
                    )
                )
            }

            override fun stringVisitor(value: String, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                if (pathStr == "stringField") {
                    assertEquals("string1", value)
                } else {
                    assert(
                        pathStr in setOf(
                            "nestedMap[\"first\"].mapSubField[\"a\"]",
                            "nestedMap[\"first\"].mapSubField[\"b\"]",
                            "nestedMap[\"first\"].mapSubField[\"c\"]",
                            "nestedMap[\"second\"].mapSubField[\"a\"]",
                            "nestedMap[\"second\"].mapSubField[\"b\"]",
                            "nestedMap[\"second\"].mapSubField[\"c\"]",
                            "nestedArray[0].mapSubField[\"a\"]",
                            "nestedArray[0].mapSubField[\"b\"]",
                            "nestedArray[0].mapSubField[\"c\"]",
                            "nestedArray[1].mapSubField[\"a\"]",
                            "nestedArray[1].mapSubField[\"b\"]",
                            "nestedArray[1].mapSubField[\"c\"]",
                            "nestedRecord.mapSubField[\"a\"]",
                            "nestedRecord.mapSubField[\"b\"]",
                            "nestedRecord.mapSubField[\"c\"]",
                        )
                    )
                    assert(
                        value in setOf(
                            "apple",
                            "blaster",
                            "cyberman"
                        )
                    )
                }
            }

            override fun bytesVisitor(
                value: ByteArray,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assert(
                    pathStr in setOf(
                        "fixedField",
                        "binaryField"
                    )
                )
            }

            override fun intVisitor(value: Int, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                val values = mapOf(
                    "intField" to 1,
                    "unionField.b" to 1,
                    "arrayField[0]" to 1,
                    "arrayField[1]" to 2,
                    "arrayField[2]" to 3,
                    "arrayField[3]" to 4,
                    "mapField[\"a\"]" to 1,
                    "mapField[\"b\"]" to 2,
                    "mapField[\"c\"]" to 3,
                    "nestedRecord.unionSubField.b" to 1,
                    "nestedRecord.arraySubField[0]" to 1,
                    "nestedRecord.arraySubField[1]" to 2,
                    "nestedRecord.arraySubField[2]" to 3,
                    "nestedRecord.arraySubField[3]" to 4,
                    "nestedRecord.mapSubField[\"a\"]" to 1,
                    "nestedRecord.mapSubField[\"b\"]" to 2,
                    "nestedRecord.mapSubField[\"c\"]" to 3,
                    "nestedRecord.intSubField" to 100,
                    "nestedArray[0].unionSubField.b" to 1,
                    "nestedArray[0].arraySubField[0]" to 1,
                    "nestedArray[0].arraySubField[1]" to 2,
                    "nestedArray[0].arraySubField[2]" to 3,
                    "nestedArray[0].arraySubField[3]" to 4,
                    "nestedArray[0].mapSubField[\"a\"]" to 1,
                    "nestedArray[0].mapSubField[\"b\"]" to 2,
                    "nestedArray[0].mapSubField[\"c\"]" to 3,
                    "nestedArray[0].intSubField" to 100,
                    "nestedArray[1].unionSubField.b" to 1,
                    "nestedArray[1].arraySubField[0]" to 1,
                    "nestedArray[1].arraySubField[1]" to 2,
                    "nestedArray[1].arraySubField[2]" to 3,
                    "nestedArray[1].arraySubField[3]" to 4,
                    "nestedArray[1].mapSubField[\"a\"]" to 1,
                    "nestedArray[1].mapSubField[\"b\"]" to 2,
                    "nestedArray[1].mapSubField[\"c\"]" to 3,
                    "nestedArray[1].intSubField" to 100,
                    "nestedMap[\"first\"].unionSubField.b" to 1,
                    "nestedMap[\"first\"].arraySubField[0]" to 1,
                    "nestedMap[\"first\"].arraySubField[1]" to 2,
                    "nestedMap[\"first\"].arraySubField[2]" to 3,
                    "nestedMap[\"first\"].arraySubField[3]" to 4,
                    "nestedMap[\"first\"].mapSubField[\"a\"]" to 1,
                    "nestedMap[\"first\"].mapSubField[\"b\"]" to 2,
                    "nestedMap[\"first\"].mapSubField[\"c\"]" to 3,
                    "nestedMap[\"first\"].intSubField" to 100,
                    "nestedMap[\"second\"].unionSubField.b" to 1,
                    "nestedMap[\"second\"].arraySubField[0]" to 1,
                    "nestedMap[\"second\"].arraySubField[1]" to 2,
                    "nestedMap[\"second\"].arraySubField[2]" to 3,
                    "nestedMap[\"second\"].arraySubField[3]" to 4,
                    "nestedMap[\"second\"].mapSubField[\"a\"]" to 1,
                    "nestedMap[\"second\"].mapSubField[\"b\"]" to 2,
                    "nestedMap[\"second\"].mapSubField[\"c\"]" to 3,
                    "nestedMap[\"second\"].intSubField" to 100
                )

                assertTrue(values.containsKey(pathStr))
                assertEquals(values[pathStr], value)
            }

            override fun longVisitor(value: Long, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals("longField", pathStr)
                assertEquals(2L, value)
            }

            override fun floatVisitor(value: Float, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals("floatField", pathStr)
                assertEquals(1.234f, value)
            }

            override fun doubleVisitor(value: Double, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals("doubleField", pathStr)
                assertEquals(5.6789.toRawBits(), value.toRawBits())
            }

            override fun booleanVisitor(
                value: Boolean,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assertEquals("booleanField", pathStr)
                assertEquals(true, value)
            }

            override fun nullVisitor(schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals("nulledUnionField", pathStr)
            }

            override fun decimalVisitor(
                value: BigDecimal,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assertEquals("decimalField", pathStr)
                assertEquals(BigDecimal.valueOf(1234567809L, 2), value)
            }

            override fun uuidVisitor(value: UUID, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals("uuidField", pathStr)
                assertEquals(UUID.nameUUIDFromBytes("hello".toByteArray(Charsets.UTF_8)), value)
            }

            override fun dateVisitor(value: LocalDate, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals("dateField", pathStr)
                assertEquals(nowDateTime.toLocalDate(), value)
            }

            override fun timeVisitor(value: LocalTime, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
                val pathStr = path.toStringPath()
                assertEquals(
                    nowDateTime.toLocalTime().truncatedTo(ChronoUnit.MILLIS),
                    value.truncatedTo(ChronoUnit.MILLIS)
                )
                if (pathStr == "timestampMicroField") {
                    assertEquals(nowDateTime.toLocalTime().truncatedTo(ChronoUnit.MICROS), value)
                }
            }

            override fun timestampVisitor(
                value: Instant,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
                val pathStr = path.toStringPath()
                assertEquals(now.toEpochMilli(), value.toEpochMilli())
                if (pathStr == "timestampMicroField") {
                    assertEquals(now.nano / 1000L, value.nano / 1000L)
                }
            }

            override fun localDateTimeVisitor(
                value: LocalDateTime,
                schema: Schema,
                path: List<PathComponent>,
                root: GenericRecord
            ) {
            }

            override fun unknownVisitor(value: Any?, schema: Schema, path: List<PathComponent>, root: GenericRecord) {
            }

        })
    }

    @Test
    fun `test path logic`() {
        val sch = PathComponent::class.java.getResourceAsStream("/uk/co/nesbit/avro/complicatedSchema.avsc")!!
            .readTextAndClose()
        val complicatedSchemaWithNesting = Schema.Parser().parse(sch)
        val record = GenericData.Record(complicatedSchemaWithNesting)
        record.putTyped("stringField", "string1")
        record.putTyped("intField", 1)
        record.putTyped("longField", 2L)
        record.putTyped("binaryField", "bytes".toByteArray(Charsets.UTF_8))
        record.putTyped("floatField", 1.234f)
        record.putTyped("doubleField", 5.6789)
        record.putTyped("booleanField", true)
        record.putTyped("fixedField", "0123456789ABCDEF".toByteArray(Charsets.UTF_8))
        val enumTemp = GenericData.EnumSymbol(complicatedSchemaWithNesting.getField("enumField").schema(), "HEARTS")
        record.putTyped("enumField", enumTemp)
        val unionRecordTypeB = GenericData.Record(complicatedSchemaWithNesting.getField("unionField").schema().types[1])
        unionRecordTypeB.putTyped("b", 1)
        record.putTyped("unionField", unionRecordTypeB)
        record.putTyped("decimalField", BigDecimal.valueOf(1234567809L, 2))
        record.putTyped("uuidField", UUID.nameUUIDFromBytes("hello".toByteArray(Charsets.UTF_8)))
        record.put("nulledUnionField", null)
        val now = Clock.systemUTC().instant()
        val nowDateTime = LocalDateTime.ofInstant(now, ZoneOffset.UTC)
        record.putTyped("dateField", nowDateTime.toLocalDate())
        record.putTyped("timeMilliField", nowDateTime.toLocalTime())
        record.putTyped("timeMicroField", nowDateTime.toLocalTime())
        record.putTyped("timestampMilliField", nowDateTime)
        record.putTyped("timestampMicroField", nowDateTime)
        record.putTyped("localTimestampMilliField", nowDateTime)
        record.putTyped("localTimestampMicroField", nowDateTime)
        val simpleArrayRecord =
            GenericData.Array<Int>(complicatedSchemaWithNesting.getField("arrayField").schema(), listOf(1, 2, 3, 4))
        record.putTyped("arrayField", simpleArrayRecord)
        val simpleMap = mapOf("a" to 1, "b" to 2, "c" to 3)
        record.putTyped("mapField", simpleMap)
        val nestedRecord = GenericData.Record(complicatedSchemaWithNesting.getField("nestedRecord").schema())
        nestedRecord.putTyped("intSubField", 100)
        nestedRecord.putTyped("unionSubField", unionRecordTypeB)
        nestedRecord.putTyped("arraySubField", simpleArrayRecord)
        val simpleMap2 = mapOf("a" to "apple", "b" to "blaster", "c" to "cyberman")
        nestedRecord.putTyped("mapSubField", simpleMap2)
        record.putTyped("nestedRecord", nestedRecord)
        val nestedArray =
            GenericData.Array<GenericRecord>(2, complicatedSchemaWithNesting.getField("nestedArray").schema())
        nestedArray.add(nestedRecord)
        nestedArray.add(nestedRecord)
        record.putTyped("nestedArray", nestedArray)
        val nestedMap = mutableMapOf<String, GenericRecord>()
        nestedMap["first"] = nestedRecord
        nestedMap["second"] = nestedRecord
        record.putTyped("nestedMap", nestedMap)
        val path1 = record.find("stringField")
        assertEquals("string1", path1.first.toString())
        assertEquals(Schema.create(Schema.Type.STRING), path1.second)
        assertFailsWith<AvroRuntimeException> { record.find("fakeField") }
        assertFailsWith<AvroRuntimeException> { record.find("string1.fakeField") }
        val path2 = record.find("arrayField[1]")
        assertEquals(2, path2.first)
        assertEquals(Schema.create(Schema.Type.INT), path2.second)
        assertFailsWith<IndexOutOfBoundsException> { record.find("arrayField[6]") }
        assertFailsWith<IndexOutOfBoundsException> { record.find("arrayField[-1]") }
        assertFailsWith<AvroRuntimeException> { record.find("arrayField.a") }
        val path3 = record.find("mapField[\"c\"]")
        assertEquals(3, path3.first)
        assertEquals(Schema.create(Schema.Type.INT), path3.second)
        assertFailsWith<AvroRuntimeException> { record.find("mapField[0]") }
        assertFailsWith<AvroRuntimeException> { record.find("mapField.a") }
    }

    @Test
    fun `Test Int Array helpers`() {
        val schemaDef = """
            {
                "name" : "Test",
                "type" : "record",
                "fields" : [
                    {
                        "name" : "intArray",
                        "type": {
                            "name": "arrayType",
                            "type": "array",
                            "items": "int"
                        }
                    }
                ]
            }
        """
        val schema = Schema.Parser().parse(schemaDef)
        val record = GenericData.Record(schema)
        val testArray = listOf(1, 2, 3, 4)
        record.putIntArray("intArray", testArray)
        val serialized = record.serialize()
        val deserialized = schema.deserialize(serialized)
        val readback = deserialized.getIntArray("intArray")
        assertEquals(testArray, readback)
        val record2 = GenericData.Record(schema)
        val testArray2 = emptyList<Int>()
        record2.putIntArray("intArray", testArray2)
        val serialized2 = record2.serialize()
        val deserialized2 = schema.deserialize(serialized2)
        val readback2 = deserialized2.getIntArray("intArray")
        assertEquals(testArray2, readback2)
    }

    @Test
    fun `Test ByteArray Array helpers`() {
        val schemaDef = """
            {
                "name" : "Test",
                "type" : "record",
                "fields" : [
                    {
                        "name" : "byteArray",
                        "type": {
                            "name": "arrayType",
                            "type": "array",
                            "items": "bytes"
                        }
                    },
                    {
                        "name" : "fixedByteArray",
                        "type": {
                            "name": "fixedArrayType",
                            "type": "array",
                            "items": {
                                "name": "fixedElementType",
                                "type": "fixed",
                                "size": 5
                            }
                        }
                    }
                ]
            }
        """
        val schema = Schema.Parser().parse(schemaDef)
        val record = GenericData.Record(schema)
        val testArray = (1..4).map { x -> ByteArray(4) { x.toByte() } }
        record.putByteArrayArray("byteArray", testArray)
        val fixedTestArray = (1..3).map { x -> ByteArray(5) { x.toByte() } }
        record.putByteArrayArray("fixedByteArray", fixedTestArray)
        val serialized = record.serialize()
        val deserialized = schema.deserialize(serialized)
        val readback = deserialized.getByteArrayArray("byteArray")
        assertEquals(testArray.size, readback.size)
        for (i in testArray.indices) {
            assertArrayEquals(testArray[i], readback[i])
        }
        val readbackFixed = deserialized.getByteArrayArray("fixedByteArray")
        assertEquals(fixedTestArray.size, readbackFixed.size)
        for (i in fixedTestArray.indices) {
            assertArrayEquals(fixedTestArray[i], readbackFixed[i])
        }
        val record2 = GenericData.Record(schema)
        val testArray2 = emptyList<ByteArray>()
        record2.putByteArrayArray("byteArray", testArray2)
        record2.putByteArrayArray("fixedByteArray", testArray2)
        val serialized2 = record2.serialize()
        val deserialized2 = schema.deserialize(serialized2)
        val readback2 = deserialized2.getByteArrayArray("byteArray")
        val readbackFixed2 = deserialized2.getByteArrayArray("byteArray")
        assertEquals(testArray2, readback2)
        assertEquals(testArray2, readbackFixed2)
    }
}