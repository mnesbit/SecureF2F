package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.services.KeyService

data class GroupHistoryEntry(
    val change: GroupChange
) : AvroConvertible {
    constructor(groupHistoryEntryRecord: GenericRecord) : this(
        groupHistoryEntryRecord.getTyped<GroupChange>("change")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupHistoryEntrySchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    GroupMemberAdd.groupMemberAddSchema.fullName to GroupMemberAdd.groupMemberAddSchema,
                    GroupMemberRemove.groupRemoveRequestSchema.fullName to GroupMemberRemove.groupRemoveRequestSchema,
                    GroupMemberModify.groupMemberModifySchema.fullName to GroupMemberModify.groupMemberModifySchema,
                    GroupModify.groupModifySchema.fullName to GroupModify.groupModifySchema,
                    GroupHistoryMerge.groupHistoryMergeSchema.fullName to GroupHistoryMerge.groupHistoryMergeSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/grouphistoryentry.avsc"))

        fun deserialize(bytes: ByteArray): GroupHistoryEntry {
            val groupHistoryEntryRecord = groupHistoryEntrySchema.deserialize(bytes)
            return GroupHistoryEntry(groupHistoryEntryRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupHistoryResponseRecord = GenericData.Record(groupHistoryEntrySchema)
        groupHistoryResponseRecord.putTyped("change", change)
        return groupHistoryResponseRecord
    }

}

data class GroupHistoryResponse(
    val senderId: SecureHash,
    val changes: List<GroupHistoryEntry>,
    val signature: DigitalSignature
) : GroupMessage {
    constructor(groupHistoryResponseRecord: GenericRecord) : this(
        groupHistoryResponseRecord.getTyped<SecureHash>("senderId"),
        groupHistoryResponseRecord.getObjectArray("changes", ::GroupHistoryEntry),
        groupHistoryResponseRecord.getTyped("signature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupHistoryResponseSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    GroupHistoryEntry.groupHistoryEntrySchema.fullName to GroupHistoryEntry.groupHistoryEntrySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/grouphistoryresponse.avsc"))

        fun deserialize(bytes: ByteArray): GroupHistoryResponse {
            val groupHistoryResponseRecord = groupHistoryResponseSchema.deserialize(bytes)
            return GroupHistoryResponse(groupHistoryResponseRecord)
        }

        fun createHistoryResponse(
            groupInfo: GroupInfo,
            senderId: SecureHash,
            changes: List<GroupChange>,
            keyService: KeyService
        ): GroupHistoryResponse {
            val senderInfo = groupInfo.findMemberById(senderId)
            require(senderInfo != null) {
                "Sender not found"
            }
            val templateObject = GroupHistoryResponse(
                senderId,
                changes.map { GroupHistoryEntry(it) },
                DigitalSignature("HISTORYRESPONSE", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService.sign(senderInfo.memberKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }

    }

    override fun toGenericRecord(): GenericRecord {
        val groupHistoryResponseRecord = GenericData.Record(groupHistoryResponseSchema)
        groupHistoryResponseRecord.putTyped("senderId", senderId)
        groupHistoryResponseRecord.putObjectArray("changes", changes)
        groupHistoryResponseRecord.putTyped("signature", signature)
        return groupHistoryResponseRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupHistoryResponse = GroupHistoryResponse(
        senderId,
        changes,
        newSignature
    )

    fun verify(groupInfo: GroupInfo) {
        val senderInfo = groupInfo.findMemberById(senderId)
        require(senderInfo != null) {
            "Sender not found"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("HISTORYRESPONSE", ByteArray(0))
        ).serialize()
        signature.verify(senderInfo.memberKey, signatureObject)
    }

}