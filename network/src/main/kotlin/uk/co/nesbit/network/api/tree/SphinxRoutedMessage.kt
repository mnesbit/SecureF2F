package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message

class SphinxRoutedMessage(val messageBytes: ByteArray) : Message {
    constructor(sphinxRoutedMessageRecord: GenericRecord) :
            this(
                    sphinxRoutedMessageRecord.getTyped<ByteArray>("messageBytes")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val sphinxRoutedMessageSchema: Schema = Schema.Parser()
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/sphinxroutedmessage.avsc"))

        fun deserialize(bytes: ByteArray): SphinxRoutedMessage {
            val sphinxRoutedMessageRecord = sphinxRoutedMessageSchema.deserialize(bytes)
            return SphinxRoutedMessage(sphinxRoutedMessageRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val sphinxRoutedMessageRecord = GenericData.Record(sphinxRoutedMessageSchema)
        sphinxRoutedMessageRecord.putTyped("messageBytes", messageBytes)
        return sphinxRoutedMessageRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SphinxRoutedMessage

        if (!messageBytes.contentEquals(other.messageBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return messageBytes.contentHashCode()
    }

}