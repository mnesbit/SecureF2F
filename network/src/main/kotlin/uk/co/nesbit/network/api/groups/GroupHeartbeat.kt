package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.SecureHash

data class GroupHeartbeat(
    val senderId: SecureHash,
    val groupStateHash: SecureHash,
    val epoch: Int
) : GroupMessage {
    constructor(groupHeartbeatRecord: GenericRecord) : this(
        groupHeartbeatRecord.getTyped("senderId"),
        groupHeartbeatRecord.getTyped("groupStateHash"),
        groupHeartbeatRecord.getTyped("epoch")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupHeartbeatSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupheartbeat.avsc"))

        fun deserialize(bytes: ByteArray): GroupHeartbeat {
            val groupHeartbeatRecord = groupHeartbeatSchema.deserialize(bytes)
            return GroupHeartbeat(groupHeartbeatRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupHeartbeatRecord = GenericData.Record(groupHeartbeatSchema)
        groupHeartbeatRecord.putTyped("senderId", senderId)
        groupHeartbeatRecord.putTyped("groupStateHash", groupStateHash)
        groupHeartbeatRecord.putTyped("epoch", epoch)
        return groupHeartbeatRecord
    }
}