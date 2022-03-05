package uk.co.nesbit.crypto.groups

import org.slf4j.Logger
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.blockdag.*
import uk.co.nesbit.crypto.contextLogger
import uk.co.nesbit.crypto.id
import java.security.PublicKey
import java.security.SignatureException
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit

class GroupManagerImpl private constructor(
    override val self: String,
    initialKey: PublicKey,
    private val sponsor: SponsorInfo?,
    private val keyManager: GroupKeyService
) : GroupManager, AutoCloseable {

    private val groupInfoBySource = mutableMapOf<SecureHash, GroupInfo>()

    private var _groupInfo: GroupInfo = GroupInfo.EmptyGroup
    override val groupInfo: GroupInfo
        get() = _groupInfo

    private data class SponsorInfo(val member: PublicKey, val address: SecureHash) {
        val memberId: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
            member.id
        }
    }

    private val blockMemberService = object : MemberService {
        val keyMappings = mutableMapOf<SecureHash, PublicKey>() // may include historic keys that are not valid now
        override val members: Set<SecureHash> = keyMappings.keys
        override fun getMemberKey(id: SecureHash): PublicKey? = keyMappings[id]
    }

    private val blockSyncManager = InMemoryBlockSyncManager(
        initialKey.id,
        blockMemberService,
        InMemoryBlockStore()
    ) { k, v ->
        keyManager.sign(k, v)
    }

    init {
        blockMemberService.keyMappings[initialKey.id] = initialKey
        if (sponsor != null) {
            blockMemberService.keyMappings[sponsor.memberId] = sponsor.member
        }
    }

    private var listenerHandle: AutoCloseable? =
        blockSyncManager.blockStore.registerDeliveryListener(::blockDeliveryListener)

    companion object {
        val log: Logger = contextLogger()

        fun createGroup(
            groupIdentifier: String,
            groupInfo: Map<String, String>,
            initialMemberName: String,
            initialMemberAddress: SecureHash,
            initialMemberInfo: Map<String, String>,
            createTime: Instant
        ): GroupManager {
            val keyManager = InMemoryGroupKeyService()
            val nodeKey = keyManager.generateSigningKey()
            val nodeDhKey = keyManager.generateDhKey()
            val groupSeed = ByteArray(32)
            keyManager.random.nextBytes(groupSeed)
            val groupId = SecureHash.secureHash(groupSeed)
            val groupCreate = GroupCreate.createGroupCreate(
                groupId,
                groupIdentifier,
                groupInfo,
                initialMemberName,
                keyManager.getSigningKey(nodeKey),
                keyManager.getDhKey(nodeDhKey),
                initialMemberAddress,
                initialMemberInfo,
                createTime.truncatedTo(ChronoUnit.MILLIS)
            ) { k, v ->
                keyManager.sign(k, v)
            }
            val groupManager = GroupManagerImpl(
                initialMemberName,
                keyManager.getSigningKey(nodeKey),
                null,
                keyManager
            )
            val initialEntry = GroupBlockPayload(groupCreate)
            groupManager.blockSyncManager.createBlock(initialEntry.serialize())
            return groupManager
        }

        fun joinGroup(
            keyManager: GroupKeyService,
            initialMemberInfo: InitialMemberDetails,
            sponsorMemberKey: PublicKey,
            sponsorAddress: SecureHash
        ): GroupManager {
            return GroupManagerImpl(
                initialMemberInfo.memberName,
                initialMemberInfo.memberKey,
                SponsorInfo(sponsorMemberKey, sponsorAddress),
                keyManager
            )
        }
    }

    override fun close() {
        listenerHandle?.close()
        listenerHandle = null
    }

    private fun mergeHeads() {
        if (blockSyncManager.blockStore.heads.size > 1) {
            val ownInfo = groupInfo.findMemberByName(self)
            if (ownInfo != null) {
                val headBlocks =
                    blockSyncManager.blockStore.heads.mapNotNull { blockSyncManager.blockStore.getBlock(it) }
                val groupsForHeads =
                    headBlocks.map { groupInfoBySource.getOrDefault(it.origin, GroupInfo.EmptyGroup) }.toSet()
                val mergeBlock = GroupMerge.createGroupMerge(
                    groupsForHeads.map { it.groupStateHash },
                    ownInfo.memberKeyId
                ) { k, v ->
                    keyManager.sign(k, v)
                }
                val groupChange = GroupBlockPayload(mergeBlock)
                blockSyncManager.createBlock(groupChange.serialize())
            }
        }
    }

    override fun groupMessageToSend(): Pair<SecureHash, BlockSyncMessage>? {
        val sponsorInfo = sponsor
        if (sponsorInfo != null && groupInfo.findMemberByName(self) == null) {
            return Pair(sponsorInfo.address, blockSyncManager.getSyncMessage(sponsorInfo.memberId))
        }
        mergeHeads()
        if (groupInfo.members.size < 2) {
            return null
        }
        for (rep in 0 until 3) {
            val (id, sync) = blockSyncManager.getSyncMessage()
            val syncAddress = groupInfo.findMemberById(id)?.routingAddress
            if (syncAddress != null) {
                return Pair(syncAddress, sync)
            }
        }
        return null
    }


    private fun updateBlockMemberKeys(message: BlockSyncMessage) {
        val blocks = message.heads + message.blocks
        for (block in blocks) {
            try {
                if (!block.isRoot) {
                    when (val change = GroupBlockPayload.deserialize(block.payload).change) {
                        is GroupCreate -> {
                            if (!blockMemberService.keyMappings.containsKey(change.initialMemberKey.id)) {
                                blockMemberService.keyMappings[change.initialMemberKey.id] = change.initialMemberKey
                            }
                        }
                        is GroupMemberAdd -> {
                            if (!blockMemberService.keyMappings.containsKey(change.newInfo.memberKeyId)) {
                                blockMemberService.keyMappings[change.newInfo.memberKeyId] =
                                    change.newInfo.memberKey
                            }
                        }
                        is GroupMemberKeyRotate -> {
                            if (change.rotateMemberKey) {
                                if (!blockMemberService.keyMappings.containsKey(change.newKey.id)) {
                                    blockMemberService.keyMappings[change.newKey.id] =
                                        change.newKey
                                }
                            }
                        }
                    }
                }
            } catch (ex: SignatureException) {
                //ignore
            }
        }
    }

    override fun processGroupMessage(message: BlockSyncMessage) {
        updateBlockMemberKeys(message)
        blockSyncManager.processSyncMessage(message)
        mergeHeads()
    }

    @Suppress("UNUSED_PARAMETER")
    private fun blockDeliveryListener(block: Block, predecessors: Set<Block>, round: Int) {
        if (block.isRoot) return
        val change = GroupBlockPayload.deserialize(block.payload)
        if (block.origin != change.change.sponsorKeyId) {
            log.info("Change must be signed by same sponsor as the block")
            return
        }
        if (change.change !is GroupMerge) {
            if (predecessors.size > 1) {
                log.info("Invalid non-merge change with two parents. Ignoring!")
                return
            }
            log.info("$self Got change ${change.change}")
            val currentGroupInfo = groupInfoBySource.getOrDefault(predecessors.single().origin, GroupInfo.EmptyGroup)
            try {
                val newGroupInfo = currentGroupInfo.applyGroupChange(change.change)
                log.info("$self Change OK")
                groupInfoBySource[block.origin] = newGroupInfo
                if (newGroupInfo.epoch > _groupInfo.epoch) {
                    _groupInfo = newGroupInfo
                }
            } catch (ex: Exception) {
                log.info("$self Change not valid ${change.change}")
            }
        } else {
            log.info("$self Got merge change ${change.change}")
            val previousGroupInfos =
                predecessors.map { groupInfoBySource.getOrDefault(it.origin, GroupInfo.EmptyGroup).groupStateHash }
                    .toSet()
            if (previousGroupInfos != change.change.previousGroupInfoHashes.toSet()) {
                log.info("State hashes don't align ignoring merge")
                return
            }
            val prevSet = blockSyncManager.blockStore.predecessorSet(setOf(block.id))
                .mapNotNull { blockSyncManager.blockStore.getBlock(it) }
            val changes = prevSet.filter { !it.isRoot }
                .map {
                    Pair(
                        blockSyncManager.blockStore.getRound(it.id),
                        GroupBlockPayload.deserialize(it.payload).change
                    )
                }

            if (changes.count { it.second is GroupCreate } != 1) {
                log.info("Not allowed to merge two groups")
                return
            }

            val phases = changes.groupBy({ it.first }, { it.second })
            var stage = 0
            var activeGroupInfo = GroupInfo.EmptyGroup
            while (true) {
                val parallelChanges = phases[stage]?.toMutableList()
                if (parallelChanges == null || parallelChanges.isEmpty()) {
                    if (stage == 0) {
                        ++stage
                        continue
                    }
                    break
                }
                if (parallelChanges.size == 1) {
                    ++stage
                    val nextChange = parallelChanges.single()
                    if (nextChange is GroupMerge) continue
                    try {
                        activeGroupInfo = activeGroupInfo.applyGroupChange(nextChange)
                        log.info("$self apply $nextChange")
                    } catch (ex: Exception) {
                        log.info("$self ignore change $nextChange due to ${ex.message}")
                    }
                    continue
                }
                while (parallelChanges.isNotEmpty()) {
                    val sponsorEpochs =
                        parallelChanges.map { activeGroupInfo.findMemberById(it.sponsorKeyId)?.issueEpoch }
                    var minSponsorEpoch: Int? = null
                    for (value in sponsorEpochs) {
                        if (minSponsorEpoch == null) {
                            minSponsorEpoch = value
                        } else if (value != null && minSponsorEpoch > value) {
                            minSponsorEpoch = value
                        }
                    }
                    val seniorChanges =
                        parallelChanges.filter { activeGroupInfo.findMemberById(it.sponsorKeyId)?.issueEpoch == minSponsorEpoch }
                    for (nextChange in seniorChanges) {
                        parallelChanges -= nextChange
                        if (nextChange is GroupMerge) continue
                        try {
                            activeGroupInfo = activeGroupInfo.applyGroupChange(nextChange)
                            log.info("apply $nextChange")
                        } catch (ex: Exception) {
                            log.info("ignore change $nextChange due to ${ex.message}")
                        }
                    }
                }
                ++stage
            }
            log.info("$self Merge OK")
            groupInfoBySource[block.origin] = activeGroupInfo
            if (activeGroupInfo.epoch > _groupInfo.epoch) {
                _groupInfo = activeGroupInfo
            }
        }
    }

    override fun changeGroupInfo(newGroupInfo: Map<String, String>) {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        if (ownInfo.role != GroupMemberRole.ADMIN) {
            throw IllegalArgumentException("Not an admin")
        }
        mergeHeads()
        val groupModify = GroupModify.createModify(
            newGroupInfo,
            ownInfo.memberKeyId
        ) { k, v ->
            keyManager.sign(k, v)
        }
        GroupBlockPayload(groupModify)
    }

    override fun addMember(
        newMember: InitialMemberDetails,
        startingRole: GroupMemberRole,
        startingInfo: Map<String, String>,
        now: Instant
    ) {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        if (ownInfo.role != GroupMemberRole.ADMIN) {
            throw IllegalArgumentException("Not an admin")
        }
        mergeHeads()
        blockMemberService.keyMappings[newMember.memberKeyId] = newMember.memberKey
        val addMember = GroupMemberAdd.createMemberAdd(
            groupInfo,
            newMember.memberName,
            newMember.memberKey,
            newMember.memberDhKey,
            newMember.routingAddress,
            ownInfo.memberKeyId,
            now,
            startingRole,
            startingInfo
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(addMember)
        blockSyncManager.createBlock(memberChange.serialize())
    }

    override fun deleteMember(memberKeyId: SecureHash) {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        if (ownInfo.role != GroupMemberRole.ADMIN) {
            throw IllegalArgumentException("Not an admin")
        }
        mergeHeads()
        val newDhKey = keyManager.generateDhKey()
        val groupMemberDelete = GroupMemberRemove.createRemoveRequest(
            groupInfo,
            memberKeyId,
            ownInfo.memberKeyId,
            keyManager.getDhKey(newDhKey)
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(groupMemberDelete)
        blockSyncManager.createBlock(memberChange.serialize())
    }

    override fun changeMemberRole(memberId: SecureHash, newRole: GroupMemberRole) {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        if (ownInfo.role != GroupMemberRole.ADMIN) {
            throw IllegalArgumentException("Not an admin")
        }
        mergeHeads()
        val memberInfo =
            groupInfo.findMemberById(memberId) ?: throw IllegalArgumentException("Can't find member $memberId")
        val groupMemberAdminModify = GroupMemberAdminChange.createGroupMemberAdminChange(
            groupInfo,
            memberInfo.memberKeyId,
            newRole,
            memberInfo.otherInfo,
            ownInfo.memberKeyId
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(groupMemberAdminModify)
        blockSyncManager.createBlock(memberChange.serialize())
    }

    override fun changeMemberInfo(memberId: SecureHash, newMemberInfo: Map<String, String>) {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        if (ownInfo.role != GroupMemberRole.ADMIN) {
            throw IllegalArgumentException("Not an admin")
        }
        mergeHeads()
        val memberInfo =
            groupInfo.findMemberById(memberId) ?: throw IllegalArgumentException("Can't find member $memberId")
        val groupMemberAdminModify = GroupMemberAdminChange.createGroupMemberAdminChange(
            groupInfo,
            memberInfo.memberKeyId,
            memberInfo.role,
            newMemberInfo,
            ownInfo.memberKeyId
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(groupMemberAdminModify)
        blockSyncManager.createBlock(memberChange.serialize())
    }

    override fun rotateKey(now: Instant): SecureHash {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        val newKey = keyManager.generateSigningKey()
        blockMemberService.keyMappings[newKey] = keyManager.getSigningKey(newKey)
        val newRoot = Block.createRootBlock(newKey) { k, v ->
            keyManager.sign(
                k,
                v
            )
        } // merge and sign new root block under old key
        blockSyncManager.blockStore.storeBlock(newRoot)
        mergeHeads()
        blockSyncManager.self = newKey // activate new key
        val groupMemberRotateKey = GroupMemberKeyRotate.createGroupMemberKeyRotate(
            groupInfo,
            ownInfo.memberKeyId,
            true,
            keyManager.getSigningKey(newKey),
            now
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(groupMemberRotateKey)
        blockSyncManager.createBlock(memberChange.serialize())
        return newKey
    }

    override fun rotateDhKey(): SecureHash {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        mergeHeads()
        val newDhKey = keyManager.generateDhKey()
        val groupMemberRotateKey = GroupMemberKeyRotate.createGroupMemberKeyRotate(
            groupInfo,
            ownInfo.memberKeyId,
            false,
            keyManager.getDhKey(newDhKey),
            Clock.systemUTC().instant()
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(groupMemberRotateKey)
        blockSyncManager.createBlock(memberChange.serialize())
        return newDhKey
    }

    override fun setNewAddress(newAddress: SecureHash) {
        val ownInfo = groupInfo.findMemberByName(self) ?: throw IllegalArgumentException("Member not found")
        mergeHeads()
        val groupMemberSetAddress = GroupMemberAddressChange.createGroupMemberAddressChange(
            groupInfo,
            ownInfo.memberKeyId,
            newAddress
        ) { k, v ->
            keyManager.sign(k, v)
        }
        val memberChange = GroupBlockPayload(groupMemberSetAddress)
        blockSyncManager.createBlock(memberChange.serialize())
    }
}