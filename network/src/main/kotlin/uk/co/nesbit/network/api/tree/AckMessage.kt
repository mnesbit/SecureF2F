package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message

class AckMessage(val ack: Boolean = true) : Message {
    constructor(ackMessageRecord: GenericRecord) : this(ackMessageRecord.getTyped<Boolean>("ack"))

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val ackMessageSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/ackmessage.avsc"))

        fun deserialize(bytes: ByteArray): AckMessage {
            val ackMessageRecord = ackMessageSchema.deserialize(bytes)
            return AckMessage(ackMessageRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val ackMessageRecord = GenericData.Record(ackMessageSchema)
        ackMessageRecord.putTyped("ack", ack)
        return ackMessageRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AckMessage

        if (ack != other.ack) return false

        return true
    }

    override fun hashCode(): Int {
        return ack.hashCode()
    }
}