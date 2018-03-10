package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.SphinxAddress
import java.util.*

class RoutedMessage private constructor(val replyTo: SphinxAddress,
                                        val payloadSchemaId: ByteArray,
                                        val payload: ByteArray) : AvroConvertible {
    constructor(routedMessageRecord: GenericRecord) :
            this(SphinxAddress(routedMessageRecord.getTyped("replyTo", ::SphinxPublicIdentity)),
                    routedMessageRecord.getTyped("payloadSchemaId"),
                    routedMessageRecord.getTyped("payload"))

    init {
        require(payloadSchemaId.size == 32) { "Invalid payloadSchemaId" }
    }

    companion object {
        val routedMessageSchema: Schema = Schema.Parser()
                .addTypes(mapOf(SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema,
                        SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
                .parse(RoutedMessage::class.java.getResourceAsStream("/uk/co/nesbit/network/api/routing/routedmessage.avsc"))

        val knownSchemas = SchemaRegistry()

        fun deserialize(bytes: ByteArray): RoutedMessage {
            val routedMessageRecord = routedMessageSchema.deserialize(bytes)
            return RoutedMessage(routedMessageRecord)
        }

        fun createRoutedMessage(from: SphinxAddress, message: Message): RoutedMessage {
            val record = message.toGenericRecord()
            val schemaId = knownSchemas.getFingeprint(record.schema)
            return RoutedMessage(from, schemaId, record.serialize())
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val routedMessageRecord = GenericData.Record(routedMessageSchema)
        routedMessageRecord.putTyped("replyTo", replyTo.identity)
        routedMessageRecord.putTyped("payloadSchemaId", payloadSchemaId)
        routedMessageRecord.putTyped("payload", payload)
        return routedMessageRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RoutedMessage

        if (replyTo != other.replyTo) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(payload, other.payload)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = replyTo.hashCode()
        result = 31 * result + Arrays.hashCode(payload)
        return result
    }

}