package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.network.api.Message


class OneHopMessage private constructor(
        private val schemaType: ByteArray,
        private val payload: ByteArray
) : Message {
    constructor(oneHopMessageRecord: GenericRecord) :
            this(
                    oneHopMessageRecord.getTyped("schemaFingerprint"),
                    oneHopMessageRecord.getTyped("payload")
            )

    init {
        require(schemaType.size == SchemaRegistry.FingerprintSize) { "Schema hash must be SHA-256" }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val oneHopMessageSchema: Schema = Schema.Parser()
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/onehopmessage.avsc"))

        private val schemas = SchemaRegistry(
            listOf(
                Pair(OneHopMessage::class.java, oneHopMessageSchema),
                Pair(Hello::class.java, Hello.helloSchema),
                Pair(TreeState::class.java, TreeState.treeStateSchema),
                Pair(GreedyRoutedMessage::class.java, GreedyRoutedMessage.greedyRoutedSchema),
                Pair(SphinxRoutedMessage::class.java, SphinxRoutedMessage.sphinxRoutedMessageSchema),
                Pair(ClientDataMessage::class.java, ClientDataMessage.clientDataMessageSchema)
            )
        )

        fun createOneHopMessage(value: Message): OneHopMessage {
            val record = value.toGenericRecord()
            val hash = schemas.safeRegisterDeserializer(value.javaClass, record.schema)
            return OneHopMessage(hash, record.serialize())
        }

        fun deserialize(bytes: ByteArray): OneHopMessage {
            val oneHopMessageRecord = oneHopMessageSchema.deserialize(bytes)
            return OneHopMessage(oneHopMessageRecord)
        }

        fun deserializePayload(bytes: ByteArray): Message {
            val message = deserialize(bytes)
            return message.payloadMessage
        }
    }

    val payloadMessage: Message by lazy(LazyThreadSafetyMode.PUBLICATION) {
        schemas.deserialize(schemaType, payload) as Message
    }

    override fun toGenericRecord(): GenericRecord {
        val oneHopMessageRecord = GenericData.Record(oneHopMessageSchema)
        oneHopMessageRecord.putTyped("schemaFingerprint", schemaType)
        oneHopMessageRecord.putTyped("payload", payload)
        return oneHopMessageRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as OneHopMessage

        if (!schemaType.contentEquals(other.schemaType)) return false
        if (!payload.contentEquals(other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaType.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }
}