package uk.co.nesbit.crypto.groups

import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.blockdag.BlockSyncMessage
import uk.co.nesbit.crypto.id
import java.security.PublicKey
import java.time.Instant

data class InitialMemberDetails(
    val memberName: String,
    val memberKey: PublicKey,
    val memberDhKey: PublicKey,
    val routingAddress: SecureHash
) {
    val memberKeyId: SecureHash by lazy { memberKey.id }
}

interface GroupManager {
    val self: String
    val groupInfo: GroupInfo

    fun changeGroupInfo(
        newGroupInfo: Map<String, String>
    )

    fun addMember(
        newMember: InitialMemberDetails,
        startingRole: GroupMemberRole,
        startingInfo: Map<String, String>,
        now: Instant
    )

    fun deleteMember(
        memberKeyId: SecureHash
    )

    fun changeMemberRole(
        memberId: SecureHash,
        newRole: GroupMemberRole
    )

    fun changeMemberInfo(
        memberId: SecureHash,
        newMemberInfo: Map<String, String>
    )

    fun rotateKey(now: Instant): SecureHash
    fun rotateDhKey(): SecureHash
    fun setNewAddress(newAddress: SecureHash)

    fun groupMessageToSend(): Pair<SecureHash, BlockSyncMessage>?
    fun processGroupMessage(message: BlockSyncMessage)
}