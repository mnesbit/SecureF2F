package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.*
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.groups.GroupMessage
import uk.co.nesbit.network.api.groups.deserializeByGroupMessageType
import uk.co.nesbit.network.api.groups.getGroupMessageType

class GroupMembershipMessage(
    val groupId: SecureHash,
    val payload: ByteArray
) : Message {
    constructor(groupMembershipMessageRecord: GenericRecord) : this(
        groupMembershipMessageRecord.getTyped("groupId"),
        groupMembershipMessageRecord.getTyped("payload"),
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMembershipMessageSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/groupmembershipmessage.avsc"))

        fun deserialize(bytes: ByteArray): GroupMembershipMessage {
            val groupMembershipMessageRecord = groupMembershipMessageSchema.deserialize(bytes)
            return GroupMembershipMessage(groupMembershipMessageRecord)
        }

        fun createGroupMembershipMessage(
            message: GroupMessage,
            groupId: SecureHash,
            messageKey: ByteArray,
            messageNonce: ByteArray
        ): GroupMembershipMessage {
            val messageType = getGroupMessageType(message)
            val payload = concatByteArrays(messageType.ordinal.toByteArray(), message.serialize())
            val encryptedMessage = chaChaEncrypt(messageKey, messageNonce, payload, groupId.serialize())
            return GroupMembershipMessage(groupId, encryptedMessage)
        }
    }

    fun decryptGroupMessage(messageKey: ByteArray, messageNonce: ByteArray): GroupMessage {
        val decryptedMessage = chaChaDecrypt(messageKey, messageNonce, payload, groupId.serialize())
        val splits = decryptedMessage.splitByteArrays(4, decryptedMessage.size - 4)
        return deserializeByGroupMessageType(splits[0].toInt(), splits[1])
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMembershipMessageRecord = GenericData.Record(groupMembershipMessageSchema)
        groupMembershipMessageRecord.putTyped("groupId", groupId)
        groupMembershipMessageRecord.putTyped("payload", payload)
        return groupMembershipMessageRecord
    }

    override fun toString(): String {
        return "GroupMembershipMessage[groupId=$groupId, payloadSize=${payload.size}]"
    }
}