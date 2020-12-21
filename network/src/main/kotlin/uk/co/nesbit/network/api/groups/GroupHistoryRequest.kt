package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash

data class GroupHistoryRequest(
    val senderId: SecureHash,
    val historicGroupHashes: List<SecureHash>
) : GroupMessage {
    constructor(groupHistoryRequestRecord: GenericRecord) : this(
        groupHistoryRequestRecord.getTyped("senderId"),
        groupHistoryRequestRecord.getObjectArray("historicGroupHashes", ::SecureHash)
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupHistoryRequestSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/grouphistoryrequest.avsc"))

        fun deserialize(bytes: ByteArray): GroupHistoryRequest {
            val groupHistoryRequestRecord = groupHistoryRequestSchema.deserialize(bytes)
            return GroupHistoryRequest(groupHistoryRequestRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupHistoryRequestRecord = GenericData.Record(groupHistoryRequestSchema)
        groupHistoryRequestRecord.putTyped("senderId", senderId)
        groupHistoryRequestRecord.putObjectArray("historicGroupHashes", historicGroupHashes)
        return groupHistoryRequestRecord
    }

}