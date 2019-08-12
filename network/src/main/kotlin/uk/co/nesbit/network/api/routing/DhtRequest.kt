package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity

class DhtRequest(
    val requestId: Long,
    val key: SecureHash,
    val replyPath: ReplyPath,
    val data: ByteArray?
) : AvroConvertible {
    constructor(dhtRequest: GenericRecord) :
            this(
                dhtRequest.getTyped("requestId"),
                dhtRequest.getTyped("key", ::SecureHash),
                dhtRequest.getTyped("replyPath", ::ReplyPath),
                dhtRequest.getTyped("data")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val dhtRequestSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    ReplyPath.replyPathSchema.fullName to ReplyPath.replyPathSchema,
                    SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/dhtrequest.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", dhtRequestSchema)

        fun deserialize(bytes: ByteArray): DhtRequest {
            val dhtRequestRecord = dhtRequestSchema.deserialize(bytes)
            return DhtRequest(dhtRequestRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val dhtRequestRecord = GenericData.Record(dhtRequestSchema)
        dhtRequestRecord.putTyped("requestId", requestId)
        dhtRequestRecord.putTyped("key", key)
        dhtRequestRecord.putTyped("replyPath", replyPath)
        dhtRequestRecord.putTyped("data", data)
        return dhtRequestRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DhtRequest

        if (requestId != other.requestId) return false
        if (key != other.key) return false
        if (replyPath != other.replyPath) return false
        if (data != null) {
            if (other.data == null) return false
            if (!data.contentEquals(other.data)) return false
        } else if (other.data != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = requestId.hashCode()
        result = 31 * result + key.hashCode()
        result = 31 * result + replyPath.hashCode()
        result = 31 * result + (data?.contentHashCode() ?: 0)
        return result
    }

}