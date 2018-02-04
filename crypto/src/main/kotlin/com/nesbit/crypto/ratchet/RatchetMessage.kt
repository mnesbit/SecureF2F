package com.nesbit.crypto.ratchet

import com.nesbit.avro.AvroConvertible
import com.nesbit.avro.deserialize
import com.nesbit.avro.getTyped
import com.nesbit.avro.putTyped
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.util.*

class RatchetMessage(val encryptedHeader: ByteArray, val encryptedPayload: ByteArray) : AvroConvertible {
    constructor(ratchetMessageRecord: GenericRecord) :
            this(ratchetMessageRecord.getTyped("encryptedHeader"),
                    ratchetMessageRecord.getTyped("encryptedPayload"))

    companion object {
        val ratchetMessageSchema: Schema = Schema.Parser().parse(RatchetMessage::class.java.getResourceAsStream("/com/nesbit/crypto/ratchet/ratchetmessage.avsc"))

        fun deserialize(bytes: ByteArray): RatchetMessage {
            val ratchetMessageRecord = ratchetMessageSchema.deserialize(bytes)
            return RatchetMessage(ratchetMessageRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val ratchetMessageRecord = GenericData.Record(ratchetMessageSchema)
        ratchetMessageRecord.putTyped("encryptedHeader", encryptedHeader)
        ratchetMessageRecord.putTyped("encryptedPayload", encryptedPayload)
        return ratchetMessageRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RatchetMessage

        if (!Arrays.equals(encryptedHeader, other.encryptedHeader)) return false
        if (!Arrays.equals(encryptedPayload, other.encryptedPayload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Arrays.hashCode(encryptedHeader)
        result = 31 * result + Arrays.hashCode(encryptedPayload)
        return result
    }
}