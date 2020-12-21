package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import uk.co.nesbit.crypto.ChaCha20Poly1305
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.groups.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.GroupMembershipMessage
import uk.co.nesbit.network.api.tree.NetworkAddressInfo
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.AEADBadTagException
import kotlin.random.Random

class GroupActor(
    private var groupInfo: GroupInfo,
    private val ownMemberName: String,
    private val keyService: KeyService,
    private val routingActor: ActorRef
) :
    UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            groupInfo: GroupInfo,
            ownMemberName: String,
            keyService: KeyService,
            routingActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(
                javaClass.enclosingClass,
                groupInfo,
                ownMemberName,
                keyService,
                routingActor
            )
        }

        private val requestId = AtomicInteger(0)

        private const val POLL_INTERVAL = 5000L
        private const val INVITE_DURATION = 120000L
        private const val SEND_TIMEOUT = 30000L
    }

    private class CheckGroup(val first: Boolean)
    private class JoinPending(val sender: ActorRef, val joinRequest: JoinGroupRequest, var sent: Boolean = false)

    private class MessageState(
        val message: GroupMessage,
        val destination: SecureHash,
        val created: Instant,
        val onSuccess: (GroupMessage) -> Unit,
        val onFailure: (GroupMessage) -> Unit
    ) {
        var sendId: Int? = null
    }

    private var selfAddress: SecureHash? = null
    private var joinPending: JoinPending? = null
    private var addressChangeSent: Boolean = false
    private val localRand = Random(keyService.random.nextLong())
    private val invites = mutableListOf<GroupInviteToken>()
    private val resolvedAddresses = mutableMapOf<SecureHash, Boolean>()
    private val pendingMessages = mutableListOf<MessageState>()
    private val groupHistory = mutableMapOf<SecureHash, GroupInfo>() // hash ->GroupInfo
    private val changeHistory = mutableMapOf<SecureHash, GroupChange>()  // output hash -> change
    private val nextNodes = mutableMapOf<SecureHash, MutableSet<SecureHash>>() // input hash -> set of output hashes

    override fun preStart() {
        super.preStart()
        val ownInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownInfo != null) {
            groupHistory[groupInfo.groupStateHash] = groupInfo
        }
        //log().info("Starting GroupActor")
        routingActor.tell(
            MessageWatchRequest(
                EnumSet.of(
                    MessageWatchTypes.ADDRESS_UPDATE,
                    MessageWatchTypes.GROUP_MEMBERSHIP_MESSAGES
                )
            ), self
        )
        timers.startSingleTimer(
            "CheckGroupsInit",
            CheckGroup(true),
            localRand.nextInt(POLL_INTERVAL.toInt()).toLong().millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped GroupActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart GroupActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is NetworkAddressInfo -> onSelfAddress(message)
            is ClientDhtResponse -> onDhtResponse(message)
            is SendGroupManagementResult -> onSendResponse(message)
            is GroupMembershipMessage -> onGroupReceiveMessage(message)
            is GroupMessage -> processGroupMessage(message)
            is CheckGroup -> onCheckGroup(message)
            is CreateGroupInviteRequest -> onCreateInvite(message)
            is GetGroupByNameRequest -> onGetGroupByName(message)
            is JoinGroupRequest -> onJoinGroupRequest(message)
            is ChangeGroupDataRequest -> onChangeGroupDataRequest(message)
            is MemberRequest -> onMemberRequest(message)
            else -> throw IllegalArgumentException("Unknown message type ${message.javaClass.name}")
        }
    }

    private fun onSelfAddress(addressInfo: NetworkAddressInfo) {
        selfAddress = addressInfo.identity.id
        if (joinPending != null && !joinPending!!.sent) {
            joinPending!!.sent = true
            processJoinGroupRequest(joinPending!!.sender, joinPending!!.joinRequest)
        }
    }

    private fun onCheckGroup(message: CheckGroup) {
        if (message.first) {
            timers.startTimerWithFixedDelay(
                "CheckGroupsPoll",
                CheckGroup(false),
                POLL_INTERVAL.millis()
            )
        }
        //log().info("Check groups")
        cleanupExpiredInvites()
        checkPendingJoinExpiry()
        checkAddress()
        sendHeartBeat()
        checkSends()
    }

    private fun cleanupExpiredInvites() {
        val now = Clock.systemUTC().instant()
        val inviteItr = invites.iterator()
        while (inviteItr.hasNext()) {
            val invite = inviteItr.next()
            if (invite.expireTime <= now) {
                inviteItr.remove()
                log().warning("invite ${invite.inviteId} expired")
            }
        }
    }

    private fun checkPendingJoinExpiry() {
        val now = Clock.systemUTC().instant()
        val pendingJoin = joinPending
        if (pendingJoin != null
            && pendingJoin.joinRequest.invite.expireTime < now
        ) {
            log().warning("pending join timed out")
            onJoinGroupFailed(pendingJoin.sender, pendingJoin.joinRequest.invite)
        }
    }

    private fun applyChange(change: GroupChange, text: String): Boolean {
        val oldGroupInfo = groupInfo
        addChangeRecord(change)
        val groupUpdated = (oldGroupInfo != groupInfo)
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo?.role == GroupMemberRole.ADMIN && groupUpdated) {
            val admins = groupInfo.admins
            val updateInfo = GroupHistoryResponse.createHistoryResponse(
                groupInfo,
                ownMemberInfo.memberKeyId,
                listOf(change),
                keyService
            )
            val now = Clock.systemUTC().instant()
            for (admin in admins) {
                if (admin.memberName != ownMemberName) {
                    val messageState = MessageState(
                        updateInfo,
                        admin.routingAddress,
                        now,
                        { _ -> log().info("$text sent ok $updateInfo") },
                        { _ -> log().info("$text not sent") },
                    )
                    pendingMessages += messageState
                }
            }
        }
        return groupUpdated
    }

    private fun checkAddress() {
        val routingAddress = selfAddress
        if (routingAddress != null
            && joinPending == null
            && groupInfo.members.isNotEmpty()
            && !addressChangeSent
        ) {
            val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
            if (ownMemberInfo != null && ownMemberInfo.routingAddress != selfAddress) {
                log().info("own routing address out of date updating")
                val newMemberInfo = ownMemberInfo.copy(
                    routingAddress = routingAddress
                )
                val changeRequest = GroupMemberModify.createModifyRequest(
                    groupInfo,
                    newMemberInfo,
                    ownMemberInfo.memberKeyId,
                    keyService
                )
                addressChangeSent = true
                applyChange(changeRequest, "Address change")
            }
        }
    }

    private fun checkSends() {
        val now = Clock.systemUTC().instant()
        val callbacks = mutableListOf<Pair<(GroupMessage) -> Unit, GroupMessage>>()
        val messageItr = pendingMessages.iterator()
        while (messageItr.hasNext()) {
            val messageState = messageItr.next()
            if (ChronoUnit.MILLIS.between(messageState.created, now) >= SEND_TIMEOUT) {
                messageItr.remove()
                log().warning("message send $messageState expired")
                callbacks += Pair(messageState.onFailure, messageState.message)
                continue
            }
            if (messageState.sendId == null) {
                if (messageState.destination == selfAddress) {
                    val messageId = requestId.getAndIncrement()
                    messageState.sendId = messageId
                    log().info("send message ${messageState.message} requestId $messageId to self")
                    self.tell(messageState.message, self)
                    messageItr.remove()
                    callbacks += Pair(messageState.onSuccess, messageState.message)
                    continue
                }
                val addressKnown = resolvedAddresses[messageState.destination]
                if (addressKnown == true) {
                    val messageId = requestId.getAndIncrement()
                    messageState.sendId = messageId
                    log().info("send message ${messageState.message} requestId $messageId to ${messageState.destination}")
                    routingActor.tell(
                        SendGroupManagementMessage(
                            messageState.destination,
                            messageId,
                            GroupMembershipMessage.createGroupMembershipMessage(
                                messageState.message,
                                groupInfo.groupId,
                                ByteArray(ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES),
                                ByteArray(ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES)
                            )
                        ), self
                    )
                } else if (addressKnown == null) {
                    log().info("send DHT lookup for ${messageState.destination}")
                    resolvedAddresses[messageState.destination] = false
                    routingActor.tell(
                        ClientDhtRequest(
                            messageState.destination,
                            null
                        ), self
                    )
                }
            }
        }
        for (callback in callbacks) {
            callback.first(callback.second)
        }
    }

    private fun sendHeartBeat() {
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (joinPending == null && groupInfo.members.size > 1 && ownMemberInfo != null) {
            log().info("send heartbeat ${groupInfo.groupStateHash}")
            val otherMembers = groupInfo.members.filter { it.memberName != ownMemberName }
            val randomTarget = otherMembers[localRand.nextInt(otherMembers.size)]
            val now = Clock.systemUTC().instant()
            val heartbeat = GroupHeartbeat(ownMemberInfo.memberKeyId, groupInfo.groupStateHash, groupInfo.epoch)
            val messageState = MessageState(
                heartbeat,
                randomTarget.routingAddress,
                now,
                { },
                { },
            )
            pendingMessages += messageState
        }
    }

    private fun onGroupHeartbeat(message: GroupHeartbeat) {
        if (joinPending == null
            && message.groupStateHash != groupInfo.groupStateHash
        ) {
            val peerInfo = groupInfo.findMemberById(message.senderId)
            if (peerInfo != null
                && message.epoch >= groupInfo.epoch
                && !changeHistory.containsKey(message.groupStateHash)
            ) {
                val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
                if (ownMemberInfo == null) {
                    log().error("can't find own info in group")
                    return
                }
                log().info("group state not consistent. Issuing a read")
                val now = Clock.systemUTC().instant()
                val historyRequest = GroupHistoryRequest(ownMemberInfo.memberKeyId, listOf(message.groupStateHash))
                val messageState = MessageState(
                    historyRequest,
                    peerInfo.routingAddress,
                    now,
                    { _ -> log().info("GroupHistoryRequest sent ok $message") },
                    { _ -> log().info("GroupHistoryRequest not sent") },
                )
                pendingMessages += messageState
                checkSends()
            }
        }
    }

    private fun onDhtResponse(message: ClientDhtResponse) {
        log().info("onDhtResponse $message")
        if (message.success) {
            resolvedAddresses[message.key] = true
            checkSends()
        } else {
            resolvedAddresses.remove(message.key)
        }
    }

    private fun onSendResponse(message: SendGroupManagementResult) {
        log().info("onSendResponse $message")
        if (!message.sent) {
            resolvedAddresses.remove(message.networkDestination)
        }
        val messageState = pendingMessages.firstOrNull {
            it.sendId == message.requestId
                    && it.destination == message.networkDestination
        }
        if (messageState != null) {
            pendingMessages.remove(messageState)
            if (message.sent) {
                log().info("message requestId ${message.requestId} sent ok")
                messageState.onSuccess(messageState.message)
            } else {
                log().info("message requestId ${message.requestId} send failed")
                messageState.onFailure(messageState.message)
            }
        }
        checkSends()
    }

    private fun addChangeRecord(change: GroupChange): Boolean {
        val prevGroupInfo = groupHistory[change.groupStateHash]
        if (prevGroupInfo != null) {
            try {
                if (change !is GroupHistoryMerge) {
                    val newGroupInfo = prevGroupInfo.applyGroupChange(change)
                    groupHistory[newGroupInfo.groupStateHash] = newGroupInfo
                    changeHistory[newGroupInfo.groupStateHash] = change
                    val nextNodes = nextNodes.getOrPut(change.groupStateHash) { mutableSetOf() }
                    nextNodes += newGroupInfo.groupStateHash
                    if (groupInfo.groupStateHash == change.groupStateHash) {
                        log().info("state updated to $newGroupInfo")
                        groupInfo = newGroupInfo
                        invites.clear()
                    }
                } else {
                    val newGroupInfo = change.applyGroupHistoryMerge(groupHistory, changeHistory)
                    groupHistory[newGroupInfo.groupStateHash] = newGroupInfo
                    changeHistory[newGroupInfo.groupStateHash] = change
                    for (predecessor in change.parentStateHashes) {
                        val nextNodes = nextNodes.getOrPut(predecessor) { mutableSetOf() }
                        nextNodes += newGroupInfo.groupStateHash
                        if (groupInfo.groupStateHash == predecessor) {
                            log().info("state updated to $newGroupInfo")
                            groupInfo = newGroupInfo
                            invites.clear()
                        }
                    }
                }
                return true
            } catch (ex: Exception) {
                log().error(ex, "unable to apply change $change")
            }
        } else {
            log().warning("unable to add $change as no predecessor")
        }
        return false
    }

    private fun onGroupReceiveMessage(message: GroupMembershipMessage) {
        log().info("received $message")
        if (message.groupId != groupInfo.groupId) {
            log().error("Message for incorrect group ${message.groupId} should be for $groupInfo")
            return
        }
        val decryptedMessage = try {
            message.decryptGroupMessage(
                ByteArray(ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES),
                ByteArray(ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES)
            )
        } catch (ex: AEADBadTagException) {
            log().error("Couldn't decode message")
            return
        }
        processGroupMessage(decryptedMessage)
    }

    private fun processGroupMessage(message: GroupMessage) {
        log().info("processGroupMessage $message")
        when (message) {
            is GroupMemberJoin -> onRemoteMemberJoinRequest(message)
            is GroupMemberWelcome -> onWelcomeMessage(message)
            is GroupHeartbeat -> onGroupHeartbeat(message)
            is GroupHistoryRequest -> onGroupHistoryRequest(message)
            is GroupHistoryResponse -> onGroupHistoryResponse(message)
            else -> log().error("unable to process ${message.javaClass.name}")
        }
    }

    private fun onRemoteMemberJoinRequest(message: GroupMemberJoin) {
        log().info("onRemoteMemberJoinRequest $message")
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo == null || ownMemberInfo.role != GroupMemberRole.ADMIN) {
            log().error("Unable to process join request")
            return
        }
        val originalInvite = invites.firstOrNull { it == message.invite }
        if (originalInvite == null) {
            log().warning("no matching invite found for $message")
            return
        }
        val now = Clock.systemUTC().instant()
        invites.remove(originalInvite)
        val groupAdd = try {
            val add = GroupMemberAdd.createMemberAdd(
                groupInfo,
                message,
                now,
                GroupMemberRole.ORDINARY,
                emptyMap(),
                keyService
            )
            add.verify(groupInfo)
            add
        } catch (ex: Exception) {
            log().error("invalid add request")
            return
        }

        if (applyChange(groupAdd, "GroupMemberAdd")) {
            val welcome = GroupMemberWelcome(
                groupInfo,
                ByteArray(ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES)
            )
            val welcomeMessageState = MessageState(
                welcome,
                message.routingAddress.id,
                now,
                { _ -> log().info("GroupMemberWelcome sent ok $welcome") },
                { _ -> onWelcomeFailed(message.routingAddress.id, welcome) },
            )
            pendingMessages += welcomeMessageState
            checkSends()
        }
    }

    private fun onWelcomeFailed(target: SecureHash, welcome: GroupMemberWelcome) {
        val now = Clock.systemUTC().instant()
        log().info("resend welcome $welcome")
        val messageState = MessageState(
            welcome,
            target,
            now,
            { msg -> log().info("join sent ok $msg") },
            { _ -> onWelcomeFailed(target, welcome) },
        )
        pendingMessages += messageState
    }

    private fun onWelcomeMessage(message: GroupMemberWelcome) {
        log().info("onWelcomeMessage $message")
        val ownMemberInfo = message.groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo == null) {
            log().error("welcome message received for someone else ${message.groupInfo}")
            return
        }
        groupInfo = message.groupInfo
        invites.clear()
        groupHistory[groupInfo.groupStateHash] = groupInfo
        val pending = joinPending
        if (pending != null) {
            joinPending = null
            pending.sender.tell(
                JoinGroupResponse(
                    true,
                    pending.joinRequest.invite.inviteId,
                    groupInfo
                ), self
            )
        }
    }

    private fun onGroupHistoryRequest(message: GroupHistoryRequest) {
        log().info("onGroupHistoryRequest $message")
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo == null) {
            log().error("can't find own membership")
            return
        }
        val sourceInfo = groupInfo.findMemberById(message.senderId)
        if (sourceInfo == null) {
            log().error("can't find source node info ${message.senderId}")
            return
        }
        val requested = message.historicGroupHashes.mapNotNull { changeHistory[it] }.toMutableList()
        if (requested.isEmpty()) {
            log().warning("don't know any states from $message")
            return
        }
        val predecessors = requested.map { changeHistory[it.groupStateHash] ?: it }
        val changeSet = mutableSetOf<GroupChange>()
        val processQueue = ArrayDeque(predecessors) // start one step back from requests
        while (processQueue.isNotEmpty()) {
            val headItem = processQueue.poll()
            changeSet += headItem
            val outputGroups = nextNodes[headItem.groupStateHash]
            if (outputGroups != null) {
                val newItems = outputGroups.flatMap { nextNodes[it] ?: emptyList() }.mapNotNull { changeHistory[it] }
                for (items in newItems) {
                    processQueue.offer(items)
                }
            }
        }
        val now = Clock.systemUTC().instant()
        val response = GroupHistoryResponse.createHistoryResponse(
            groupInfo,
            ownMemberInfo.memberKeyId,
            changeSet.toList(),
            keyService
        )
        log().info("send $response for $message")
        val messageState = MessageState(
            response,
            sourceInfo.routingAddress,
            now,
            { _ -> log().info("GroupHistoryResponse sent ok $response") },
            { _ -> log().warning("GroupHistoryResponse send failed $response") },
        )
        pendingMessages += messageState
        checkSends()
    }

    private fun onGroupHistoryResponse(message: GroupHistoryResponse) {
        log().info("onGroupHistoryResponse $message")
        try {
            message.verify(groupInfo)
        } catch (ex: Exception) {
            log().error(ex, "unable to validate GroupHistoryResponse $message")
            return
        }
        var update = true
        val changeList = message.changes.map { it.change }.toMutableList()
        while (update) {
            update = false
            val changeListItr = changeList.iterator()
            while (changeListItr.hasNext()) {
                val groupChange = changeListItr.next()
                val prevGroupInfo = groupHistory[groupChange.groupStateHash]
                if (prevGroupInfo != null) {
                    if (addChangeRecord(groupChange)) {
                        update = true
                    }
                    changeListItr.remove()
                }
            }
        }
        val graphSinks = groupHistory.keys.filter { !nextNodes.containsKey(it) }
        log().info("head nodes ${graphSinks.size} $graphSinks")

        val now = Clock.systemUTC().instant()
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (changeList.isEmpty() && ownMemberInfo?.role == GroupMemberRole.ADMIN && graphSinks.size > 1) {
            val heads = graphSinks.mapNotNull { groupHistory[it] }
            if (heads.size > 1) {
                val merge = GroupHistoryMerge.createGroupHistoryMerge(heads, ownMemberInfo.memberKeyId, keyService)
                applyChange(merge, "GroupHistoryMerge")
                return
            }
        }
        val sourceMemberInfo = groupInfo.findMemberById(message.senderId)
        if (changeList.isNotEmpty() && ownMemberInfo != null && sourceMemberInfo != null) {
            val historyRequest = GroupHistoryRequest(
                ownMemberInfo.memberKeyId,
                changeList.flatMap { if (it is GroupHistoryMerge) it.parentStateHashes else listOf(it.groupStateHash) }
            )
            val messageState = MessageState(
                historyRequest,
                sourceMemberInfo.routingAddress,
                now,
                { _ -> log().info("History request sent ok $message") },
                { _ -> log().info("History request not sent $message") },
            )
            pendingMessages += messageState
            checkSends()
        }
    }

    private fun onCreateInvite(message: CreateGroupInviteRequest) {
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo == null || ownMemberInfo.role != GroupMemberRole.ADMIN) {
            sender.tell(
                CreateGroupInviteResponse(
                    false,
                    groupInfo.groupId,
                    null
                ), self
            )
            return
        }
        val expiryTime = Clock.systemUTC().instant().plusMillis(INVITE_DURATION)
        val newInvite = try {
            GroupInviteToken.createInvite(
                groupInfo,
                expiryTime,
                groupInfo.findMemberByName(ownMemberName)!!.memberKeyId,
                keyService
            )
        } catch (ex: Exception) {
            log().error(ex, "unable to create invite for $message")
            sender.tell(CreateGroupInviteResponse(false, message.groupId, null), self)
            return
        }
        invites += newInvite
        sender.tell(CreateGroupInviteResponse(true, newInvite.groupId, newInvite), self)
    }

    private fun onGetGroupByName(message: GetGroupByNameRequest) {
        if (message.identifier != groupInfo.groupIdentifier) {
            log().error("incorrect request by name")
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
        sender.tell(
            GroupCommandResponse(
                true,
                groupInfo
            ), self
        )
    }

    private fun onJoinGroupRequest(message: JoinGroupRequest) {
        joinPending = JoinPending(sender, message)
        if (selfAddress == null) {
            return
        }
        processJoinGroupRequest(sender, message)
    }

    private fun processJoinGroupRequest(source: ActorRef, message: JoinGroupRequest) {
        val now = Clock.systemUTC().instant()
        val groupKey = keyService.generateSigningKey()
        val joinMessage = GroupMemberJoin.createJoinRequest(
            message.invite,
            message.ownMemberName,
            groupKey,
            selfAddress!!,
            keyService
        )
        val messageState = MessageState(
            joinMessage,
            message.invite.sponsorAddress,
            now,
            { _ -> log().info("join sent ok $message") },
            { _ -> onJoinGroupFailed(source, message.invite) },
        )
        pendingMessages += messageState
        checkSends()
    }

    private fun onJoinGroupFailed(originator: ActorRef, invite: GroupInviteToken) {
        val now = Clock.systemUTC().instant()
        if (invite.expireTime > now) {
            val groupKey = keyService.generateSigningKey()
            val joinMessage = GroupMemberJoin.createJoinRequest(
                invite,
                ownMemberName,
                groupKey,
                selfAddress!!,
                keyService
            )
            log().info("resend join $joinMessage")
            val messageState = MessageState(
                joinMessage,
                invite.sponsorAddress,
                now,
                { msg -> log().info("join sent ok $msg") },
                { _ -> onJoinGroupFailed(originator, invite) },
            )
            pendingMessages += messageState
            return
        }
        originator.tell(JoinGroupResponse(false, invite.inviteId, null), self)
        context.stop(self)
        joinPending = null
    }

    private fun onChangeGroupDataRequest(message: ChangeGroupDataRequest) {
        log().info("onChangeGroupDataRequest $message")
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo == null || ownMemberInfo.role != GroupMemberRole.ADMIN) {
            sender.tell(
                GroupCommandResponse(
                    false,
                    groupInfo
                ), self
            )
            return
        }
        val modifyRequest = GroupModify.createModify(
            groupInfo,
            message.newData,
            ownMemberInfo.memberKeyId,
            keyService

        )
        applyChange(modifyRequest, "GroupModify")
    }

    private fun onMemberRequest(message: MemberRequest) {
        log().info("onMemberRequest $message")
        val ownMemberInfo = groupInfo.findMemberByName(ownMemberName)
        if (ownMemberInfo == null || ownMemberInfo.role != GroupMemberRole.ADMIN) {
            sender.tell(
                GroupCommandResponse(
                    false,
                    groupInfo
                ), self
            )
            return
        }
        val memberInfo = groupInfo.findMemberById(message.memberId)
        if (memberInfo == null) {
            sender.tell(
                GroupCommandResponse(
                    false,
                    groupInfo
                ), self
            )
            return
        }
        val now = Clock.systemUTC().instant()
        val changeRequest: GroupChange = when (message) {
            is RemoveMemberRequest -> {
                val newDhKey = keyService.generateDhKey()
                GroupMemberRemove.createRemoveRequest(
                    groupInfo,
                    memberInfo.memberKeyId,
                    ownMemberInfo.memberKeyId,
                    newDhKey,
                    keyService
                )
            }
            is ChangeMemberRoleRequest -> {
                val newMemberInfo = memberInfo.copy(
                    role = message.newRole
                )
                GroupMemberModify.createModifyRequest(
                    groupInfo,
                    newMemberInfo,
                    ownMemberInfo.memberKeyId,
                    keyService
                )
            }
            is ChangeMemberKeyRequest -> {
                val expiredKeyEntry = HistoricKeyInfo(
                    keyService.getSigningKey(memberInfo.memberKeyId),
                    memberInfo.keyIssued,
                    now
                )
                val newHistoricKeys = memberInfo.historicKeys + expiredKeyEntry
                val newKey = keyService.generateSigningKey()
                val newMemberInfo = memberInfo.copy(
                    memberKey = keyService.getSigningKey(newKey),
                    keyIssued = now,
                    historicKeys = newHistoricKeys
                )
                GroupMemberModify.createModifyRequest(
                    groupInfo,
                    newMemberInfo,
                    ownMemberInfo.memberKeyId,
                    keyService
                )
            }
            is ChangeMemberDhKeyRequest -> {
                val newDhKey = keyService.generateDhKey()
                val newMemberInfo = memberInfo.copy(
                    groupDhKey = keyService.getDhKey(newDhKey)
                )
                GroupMemberModify.createModifyRequest(
                    groupInfo,
                    newMemberInfo,
                    ownMemberInfo.memberKeyId,
                    keyService
                )
            }
            else -> {
                log().error("Don't know command")
                sender.tell(
                    GroupCommandResponse(
                        false,
                        groupInfo
                    ), self
                )
                return
            }
        }
        try {
            changeRequest.verify(groupInfo)
        } catch (ex: java.lang.Exception) {
            log().error(ex, "Invalid member change")
            sender.tell(
                GroupCommandResponse(
                    false,
                    groupInfo
                ), self
            )
            return
        }
        if (applyChange(changeRequest, "MemberChange")) {
            val updateInfo = GroupHistoryResponse.createHistoryResponse(
                groupInfo,
                ownMemberInfo.memberKeyId,
                listOf(changeRequest),
                keyService
            )
            val clientChangeState = MessageState(
                updateInfo,
                memberInfo.routingAddress,
                now,
                { _ -> log().info("MemberChange sent to changee ok $message") },
                { _ -> onMemberChangeFailed(memberInfo.routingAddress, updateInfo) },
            )
            pendingMessages += clientChangeState
            checkSends()
            sender.tell(
                GroupCommandResponse(
                    true,
                    groupInfo
                ), self
            )
        } else {
            sender.tell(
                GroupCommandResponse(
                    false,
                    groupInfo
                ), self
            )
        }
    }

    private fun onMemberChangeFailed(target: SecureHash, change: GroupHistoryResponse) {
        val now = Clock.systemUTC().instant()
        log().info("resend member change $change")
        val messageState = MessageState(
            change,
            target,
            now,
            { msg -> log().info("join sent ok $msg") },
            { _ -> onMemberChangeFailed(target, change) },
        )
        pendingMessages += messageState
    }
}