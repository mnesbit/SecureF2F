package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped

class GroupBlockPayload(val change: GroupChange) : AvroConvertible {
    constructor(groupBlockRecord: GenericRecord) : this(
        groupBlockRecord.getTyped<GroupChange>("change")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupBlockSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    GroupCreate.groupCreateSchema.fullName to GroupCreate.groupCreateSchema,
                    GroupModify.groupModifySchema.fullName to GroupModify.groupModifySchema,
                    GroupMemberAdd.groupMemberAddSchema.fullName to GroupMemberAdd.groupMemberAddSchema,
                    GroupMemberRemove.groupRemoveRequestSchema.fullName to GroupMemberRemove.groupRemoveRequestSchema,
                    GroupMemberAdminChange.groupMemberAdminChangeSchema.fullName to GroupMemberAdminChange.groupMemberAdminChangeSchema,
                    GroupMemberKeyRotate.groupMemberKeyRotateSchema.fullName to GroupMemberKeyRotate.groupMemberKeyRotateSchema,
                    GroupMemberAddressChange.groupMemberAddressChangeSchema.fullName to GroupMemberAddressChange.groupMemberAddressChangeSchema,
                    GroupMerge.groupMergeSchema.fullName to GroupMerge.groupMergeSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupblockpayload.avsc"))

        fun deserialize(bytes: ByteArray): GroupBlockPayload {
            val groupBlockRecord = groupBlockSchema.deserialize(bytes)
            return GroupBlockPayload(groupBlockRecord)
        }

    }

    override fun toGenericRecord(): GenericRecord {
        val groupBlockRecord = GenericData.Record(groupBlockSchema)
        groupBlockRecord.putTyped("change", change)
        return groupBlockRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupBlockPayload

        if (change != other.change) return false

        return true
    }

    override fun hashCode(): Int {
        return change.hashCode()
    }

}