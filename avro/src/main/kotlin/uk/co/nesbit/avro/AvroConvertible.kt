package uk.co.nesbit.avro

import org.apache.avro.generic.GenericRecord

interface AvroConvertible {
    fun toGenericRecord(): GenericRecord
}

fun AvroConvertible.serialize(): ByteArray = this.toGenericRecord().serialize()

fun AvroConvertible.serializeJSON(): String = this.toGenericRecord().serializeJSON()