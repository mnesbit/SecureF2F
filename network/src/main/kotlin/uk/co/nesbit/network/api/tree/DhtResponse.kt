package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.network.api.Message

class DhtResponse(
        val requestId: Long,
        val nearestPaths: List<NetworkAddressInfo>,
        val data: ByteArray?
) : Message {
    constructor(dhtResponse: GenericRecord) :
            this(
                    dhtResponse.getTyped("requestId"),
                    dhtResponse.getObjectArray("nearestPaths", ::NetworkAddressInfo),
                    dhtResponse.getTyped("data")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val dhtResponseSchema: Schema = Schema.Parser()
                .addTypes(
                        mapOf(
                                NetworkAddressInfo.networkAddressInfoSchema.fullName to NetworkAddressInfo.networkAddressInfoSchema
                        )
                )
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/dhtresponse.avsc"))

        fun deserialize(bytes: ByteArray): DhtResponse {
            val dhtResponseRecord = dhtResponseSchema.deserialize(bytes)
            return DhtResponse(dhtResponseRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val dhtResponseRecord = GenericData.Record(dhtResponseSchema)
        dhtResponseRecord.putTyped("requestId", requestId)
        dhtResponseRecord.putObjectArray("nearestPaths", nearestPaths)
        dhtResponseRecord.putTyped("data", data)
        return dhtResponseRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as DhtResponse

        if (requestId != other.requestId) return false
        if (nearestPaths != other.nearestPaths) return false
        if (data != null) {
            if (other.data == null) return false
            if (!data.contentEquals(other.data)) return false
        } else if (other.data != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = requestId.hashCode()
        result = 31 * result + nearestPaths.hashCode()
        result = 31 * result + (data?.contentHashCode() ?: 0)
        return result
    }

}