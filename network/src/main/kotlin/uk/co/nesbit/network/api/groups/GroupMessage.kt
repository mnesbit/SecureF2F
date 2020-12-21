package uk.co.nesbit.network.api.groups

import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.crypto.SecureHash

interface GroupMessage : AvroConvertible

interface GroupChange : AvroConvertible {
    fun verify(groupInfo: GroupInfo)
    val groupStateHash: SecureHash
}

enum class GroupMessageType {
    MEMBER_JOIN,
    MEMBER_WELCOME,
    GROUP_HEARTBEAT,
    GROUP_HISTORY_REQUEST,
    GROUP_HISTORY_RESPONSE
}

fun getGroupMessageType(message: GroupMessage): GroupMessageType {
    return when (message) {
        is GroupMemberJoin -> GroupMessageType.MEMBER_JOIN
        is GroupMemberWelcome -> GroupMessageType.MEMBER_WELCOME
        is GroupHeartbeat -> GroupMessageType.GROUP_HEARTBEAT
        is GroupHistoryRequest -> GroupMessageType.GROUP_HISTORY_REQUEST
        is GroupHistoryResponse -> GroupMessageType.GROUP_HISTORY_RESPONSE
        else -> throw IllegalArgumentException("Unrecognised group message type ${message.javaClass.name}")
    }
}

fun deserializeByGroupMessageType(messageTypeOrdinal: Int, bytes: ByteArray): GroupMessage {
    return when (messageTypeOrdinal) {
        GroupMessageType.MEMBER_JOIN.ordinal -> GroupMemberJoin.deserialize(bytes)
        GroupMessageType.MEMBER_WELCOME.ordinal -> GroupMemberWelcome.deserialize(bytes)
        GroupMessageType.GROUP_HEARTBEAT.ordinal -> GroupHeartbeat.deserialize(bytes)
        GroupMessageType.GROUP_HISTORY_REQUEST.ordinal -> GroupHistoryRequest.deserialize(bytes)
        GroupMessageType.GROUP_HISTORY_RESPONSE.ordinal -> GroupHistoryResponse.deserialize(bytes)
        else -> throw IllegalArgumentException("Unknown message type $messageTypeOrdinal")
    }
}