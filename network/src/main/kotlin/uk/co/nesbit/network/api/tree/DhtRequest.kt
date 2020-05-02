package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.Message

class DhtRequest(
    val requestId: Long,
    val key: SecureHash,
    val sourceAddress: NetworkAddressInfo,
    val push: List<NetworkAddressInfo>,
    val data: ByteArray?
) : Message {
    constructor(dhtRequest: GenericRecord) :
            this(
                dhtRequest.getTyped("requestId"),
                dhtRequest.getTyped("key"),
                dhtRequest.getTyped("sourceAddress"),
                dhtRequest.getObjectArray("push", ::NetworkAddressInfo),
                dhtRequest.getTyped("data")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val dhtRequestSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    NetworkAddressInfo.networkAddressInfoSchema.fullName to NetworkAddressInfo.networkAddressInfoSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/dhtrequest.avsc"))

        fun deserialize(bytes: ByteArray): DhtRequest {
            val dhtRequestRecord = dhtRequestSchema.deserialize(bytes)
            return DhtRequest(dhtRequestRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val dhtRequestRecord = GenericData.Record(dhtRequestSchema)
        dhtRequestRecord.putTyped("requestId", requestId)
        dhtRequestRecord.putTyped("key", key)
        dhtRequestRecord.putTyped("sourceAddress", sourceAddress)
        dhtRequestRecord.putObjectArray("push", push)
        dhtRequestRecord.putTyped("data", data)
        return dhtRequestRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DhtRequest

        if (requestId != other.requestId) return false
        if (key != other.key) return false
        if (sourceAddress != other.sourceAddress) return false
        if (push != other.push) return false
        if (data != null) {
            if (other.data == null) return false
            if (!data.contentEquals(other.data)) return false
        } else if (other.data != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = requestId.hashCode()
        result = 31 * result + key.hashCode()
        result = 31 * result + sourceAddress.hashCode()
        result = 31 * result + push.hashCode()
        result = 31 * result + (data?.contentHashCode() ?: 0)
        return result
    }

}