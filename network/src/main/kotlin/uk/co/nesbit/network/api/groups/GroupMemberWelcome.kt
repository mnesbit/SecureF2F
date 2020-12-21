package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped

class GroupMemberWelcome(
    val groupInfo: GroupInfo,
    val groupSecret: ByteArray
) : GroupMessage {
    constructor(groupMemberWelcomeRecord: GenericRecord) : this(
        groupMemberWelcomeRecord.getTyped("groupInfo"),
        groupMemberWelcomeRecord.getTyped("groupSecret")
    )

    init {
        require(groupSecret.size >= 32) {
            "Group secret too small"
        }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberWelcomeSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    GroupInfo.groupInfoSchema.fullName to GroupInfo.groupInfoSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupmemberwelcome.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberWelcome {
            val groupMemberWelcomeRecord = groupMemberWelcomeSchema.deserialize(bytes)
            return GroupMemberWelcome(groupMemberWelcomeRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberWelcomeRecord = GenericData.Record(groupMemberWelcomeSchema)
        groupMemberWelcomeRecord.putTyped("groupInfo", groupInfo)
        groupMemberWelcomeRecord.putTyped("groupSecret", groupSecret)
        return groupMemberWelcomeRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberWelcome

        if (groupInfo != other.groupInfo) return false
        if (!groupSecret.contentEquals(other.groupSecret)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = groupInfo.hashCode()
        result = 31 * result + groupSecret.contentHashCode()
        return result
    }

}