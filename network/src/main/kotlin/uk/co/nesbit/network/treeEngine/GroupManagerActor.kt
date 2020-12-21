package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.groups.GroupInfo
import uk.co.nesbit.network.api.groups.GroupInviteToken
import uk.co.nesbit.network.api.groups.GroupMemberRole
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.NetworkAddressInfo
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import java.time.Clock
import java.util.*

data class CreateNewGroupRequest(
    val identifier: String,
    val ownMemberName: String,
    val groupInfo: Map<String, String>
)

class GetGroupsRequest

data class GroupSummary(val groupIdentifier: String, val groupId: SecureHash)
data class GetGroupsResponse(val groups: List<GroupSummary>)

data class GetGroupByNameRequest(
    val identifier: String
)

data class GroupCommandResponse(
    val ok: Boolean,
    val groupInfo: GroupInfo
)

data class CreateGroupInviteRequest(
    val groupId: SecureHash
)

data class CreateGroupInviteResponse(
    val ok: Boolean,
    val groupId: SecureHash,
    val invite: GroupInviteToken?
)

data class JoinGroupRequest(
    val ownMemberName: String,
    val invite: GroupInviteToken
)

data class JoinGroupResponse(
    val ok: Boolean,
    val inviteId: SecureHash,
    val groupInfo: GroupInfo?
)

interface MemberRequest {
    val groupId: SecureHash
    val memberId: SecureHash
}

data class RemoveMemberRequest(
    override val groupId: SecureHash,
    override val memberId: SecureHash
) : MemberRequest

data class ChangeMemberRoleRequest(
    override val groupId: SecureHash,
    override val memberId: SecureHash,
    val newRole: GroupMemberRole
) : MemberRequest

data class ChangeMemberKeyRequest(
    override val groupId: SecureHash,
    override val memberId: SecureHash
) : MemberRequest

data class ChangeMemberDhKeyRequest(
    override val groupId: SecureHash,
    override val memberId: SecureHash
) : MemberRequest

data class ChangeGroupDataRequest(
    val groupId: SecureHash,
    val newData: Map<String, String>
)

data class ChangeMemberDataRequest(
    override val groupId: SecureHash,
    override val memberId: SecureHash,
    val newData: Map<String, String>
) : MemberRequest

class GroupManagerActor(
    private val keyService: KeyService,
    private val routingActor: ActorRef
) :
    UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            routingActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, routingActor)
        }
    }

    private class GroupActorInfo(
        val name: String,
        val groupId: SecureHash,
        val groupActor: ActorRef
    )

    private var selfAddress: SecureHash? = null
    private val groups = mutableMapOf<String, SecureHash>()
    private val groupActors = mutableMapOf<SecureHash, GroupActorInfo>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting GroupManagerActor")
        routingActor.tell(
            MessageWatchRequest(
                EnumSet.of(
                    MessageWatchTypes.ADDRESS_UPDATE
                )
            ), self
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped GroupManagerActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart GroupManagerActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is Terminated -> onDeath(message)
            is NetworkAddressInfo -> onSelfAddress(message)
            is CreateNewGroupRequest -> onCreateGroup(message)
            is ChangeGroupDataRequest -> onChangeGroupData(message)
            is CreateGroupInviteRequest -> onCreateGroupInvite(message)
            is JoinGroupRequest -> onJoinGroupRequest(message)
            is MemberRequest -> onMemberRequest(message)
            is GetGroupByNameRequest -> onGroupByName(message)
            is GetGroupsRequest -> onGetGroups()
            else -> throw IllegalArgumentException("Unknown message type ${message.javaClass.name}")
        }
    }

    private fun onGetGroups() {
        log().info("onGetGroups")
        sender.tell(
            GetGroupsResponse(
                groups.entries.map { GroupSummary(it.key, it.value) }
            ), self
        )
    }

    private fun onDeath(message: Terminated) {
        log().warning("group actor died ${message.actor}")
        val group = groupActors.values.firstOrNull { it.groupActor == message.actor }
        if (group != null) {
            groupActors.remove(group.groupId)
            groups.remove(group.name)
        }
    }

    private fun onSelfAddress(addressInfo: NetworkAddressInfo) {
        selfAddress = addressInfo.identity.id
    }

    private fun onCreateGroup(message: CreateNewGroupRequest) {
        log().info("onCreateGroup $message")
        if (selfAddress == null) {
            log().warning("Not ready to create group")
            sender.tell(
                GroupCommandResponse(
                    false, GroupInfo(
                        SecureHash.secureHash("BAD_GROUP"),
                        message.identifier,
                        -1,
                        emptyList(),
                        message.groupInfo,
                        SecureHash.EMPTY_HASH
                    )
                ), self
            )
            return
        }
        val now = Clock.systemUTC().instant()
        val newGroupInfo = GroupInfo.createInitialGroup(
            message.identifier,
            message.groupInfo,
            message.ownMemberName,
            emptyMap(),
            selfAddress!!,
            now,
            keyService
        )
        log().info("new group created $newGroupInfo")
        val groupActor = context.actorOf(
            GroupActor.getProps(
                newGroupInfo,
                message.ownMemberName,
                keyService,
                routingActor
            ),
            message.identifier
        )
        groupActors[newGroupInfo.groupId] = GroupActorInfo(message.identifier, newGroupInfo.groupId, groupActor)
        groups[newGroupInfo.groupIdentifier] = newGroupInfo.groupId
        context.watch(groupActor)
        sender.tell(
            GroupCommandResponse(true, newGroupInfo),
            self
        )
    }

    private fun onCreateGroupInvite(message: CreateGroupInviteRequest) {
        log().info("onCreateGroupInvite $message")
        if (selfAddress == null) {
            log().warning("Not ready to create invite")
            sender.tell(CreateGroupInviteResponse(false, message.groupId, null), self)
            return
        }
        val groupActor = groupActors[message.groupId]
        if (groupActor == null) {
            log().error("Group not found")
            sender.tell(CreateGroupInviteResponse(false, message.groupId, null), self)
            return
        }
        groupActor.groupActor.forward(message, context)
    }

    private fun onJoinGroupRequest(message: JoinGroupRequest) {
        log().info("onJoinGroupRequest $message")
        if (selfAddress == null) {
            sender.tell(JoinGroupResponse(false, message.invite.inviteId, null), self)
            return
        }
        if (groupActors.containsKey(message.invite.groupId)) {
            log().warning("Reject JoinGroupRequest already have a (pending?) group for $message")
            sender.tell(JoinGroupResponse(false, message.invite.inviteId, null), self)
            return
        }
        log().info("pending group created ${message.invite.groupIdentifier}")
        val temporaryGroup = GroupInfo(
            message.invite.groupId,
            message.invite.groupIdentifier,
            -1,
            emptyList(),
            emptyMap(),
            SecureHash.EMPTY_HASH
        )
        val groupActor = context.actorOf(
            GroupActor.getProps(
                temporaryGroup,
                message.ownMemberName,
                keyService,
                routingActor
            ),
            message.invite.groupIdentifier
        )
        groupActors[temporaryGroup.groupId] =
            GroupActorInfo(message.invite.groupIdentifier, message.invite.groupId, groupActor)
        groups[temporaryGroup.groupIdentifier] = temporaryGroup.groupId
        context.watch(groupActor)
        groupActor.forward(message, context)
    }

    private fun onGroupByName(message: GetGroupByNameRequest) {
        log().info("onGroupByName $message")
        val group = groups[message.identifier]
        if (group == null) {
            sender.tell(
                GroupCommandResponse(
                    false, GroupInfo(
                        SecureHash.secureHash("BAD_GROUP"),
                        message.identifier,
                        -1,
                        emptyList(),
                        emptyMap(),
                        SecureHash.EMPTY_HASH
                    )
                ), self
            )
            return
        }
        val groupActor = groupActors[group]
        if (groupActor == null) {
            sender.tell(
                GroupCommandResponse(
                    false, GroupInfo(
                        SecureHash.secureHash("BAD_GROUP"),
                        message.identifier,
                        -1,
                        emptyList(),
                        emptyMap(),
                        SecureHash.EMPTY_HASH
                    )
                ), self
            )
            return
        }
        groupActor.groupActor.forward(message, context)
    }

    private fun onMemberRequest(message: MemberRequest) {
        log().info("onMemberRequest $message")
        val groupActor = groupActors[message.groupId]
        if (groupActor == null) {
            log().error("Group not found")
            sender.tell(
                GroupCommandResponse(
                    false, GroupInfo(
                        SecureHash.secureHash("BAD_GROUP"),
                        "BAD_GROUP",
                        -1,
                        emptyList(),
                        emptyMap(),
                        message.groupId
                    )
                ), self
            )
            return
        }
        groupActor.groupActor.forward(message, context)
    }

    private fun onChangeGroupData(message: ChangeGroupDataRequest) {
        log().info("onChangeGroupData $message")
        val groupActor = groupActors[message.groupId]
        if (groupActor == null) {
            log().error("Group not found")
            sender.tell(
                GroupCommandResponse(
                    false, GroupInfo(
                        SecureHash.secureHash("BAD_GROUP"),
                        "BAD_GROUP",
                        -1,
                        emptyList(),
                        emptyMap(),
                        message.groupId
                    )
                ), self
            )
            return
        }
        groupActor.groupActor.forward(message, context)
    }

}