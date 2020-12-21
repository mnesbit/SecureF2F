package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.merkle.MerkleTree
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.services.KeyService
import java.time.Instant
import java.time.temporal.ChronoUnit

data class GroupInfo(
    val groupId: SecureHash,
    val groupIdentifier: String,
    val epoch: Int,
    val members: List<GroupMemberInfo>,
    val groupInfo: Map<String, String>,
    val prevGroupStateHash: SecureHash,
) : AvroConvertible {
    constructor(groupInfoRecord: GenericRecord) : this(
        groupInfoRecord.getTyped("groupId"),
        groupInfoRecord.getTyped("groupIdentifier"),
        groupInfoRecord.getTyped("epoch"),
        groupInfoRecord.getObjectArray("members", ::GroupMemberInfo),
        groupInfoRecord.getTyped<Map<String, String>>("groupInfo").toSortedMap(),
        groupInfoRecord.getTyped("prevGroupStateHash"),
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupInfoSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    GroupMemberInfo.groupMemberInfoSchema.fullName to GroupMemberInfo.groupMemberInfoSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupinfo.avsc"))

        fun deserialize(bytes: ByteArray): GroupInfo {
            val groupInfoRecord = groupInfoSchema.deserialize(bytes)
            return GroupInfo(groupInfoRecord)
        }

        fun createInitialGroup(
            groupName: String,
            groupInfo: Map<String, String>,
            initialMemberName: String,
            initialMemberInfo: Map<String, String>,
            routingAddress: SecureHash,
            now: Instant,
            keyService: KeyService
        ): GroupInfo {
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val memberKey = keyService.generateSigningKey()
            val dhKey = keyService.generateDhKey()
            val initialMember = GroupMemberInfo(
                initialMemberName,
                keyService.getSigningKey(memberKey),
                truncatedNow,
                0,
                memberKey,
                GroupMemberRole.ADMIN,
                initialMemberInfo.toSortedMap(),
                emptyList(),
                keyService.getDhKey(dhKey),
                routingAddress
            )
            val randBytes = ByteArray(32)
            keyService.random.nextBytes(
                concatByteArrays(
                    randBytes,
                    groupName.toByteArray(Charsets.UTF_8),
                    now.toEpochMilli().toByteArray()
                )
            )
            val groupId = SecureHash.secureHash(randBytes)
            return GroupInfo(
                groupId,
                groupName,
                0,
                listOf(initialMember),
                groupInfo,
                SecureHash.Companion.secureHash(groupId.serialize())
            )
        }
    }

    val groupStateHash: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val baseBytes = this.copy(members = emptyList()).serialize()
        val treeBytes = members.map { it.serialize() } + baseBytes
        val merkleTree = MerkleTree(treeBytes)
        merkleTree.root
    }

    override fun toGenericRecord(): GenericRecord {
        val groupInfoRecord = GenericData.Record(groupInfoSchema)
        groupInfoRecord.putTyped("groupId", groupId)
        groupInfoRecord.putTyped("groupIdentifier", groupIdentifier)
        groupInfoRecord.putTyped("epoch", epoch)
        groupInfoRecord.putObjectArray("members", members)
        groupInfoRecord.putTyped("groupInfo", groupInfo.toSortedMap())
        groupInfoRecord.putTyped("prevGroupStateHash", prevGroupStateHash)
        return groupInfoRecord
    }

    private val repr: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val buffer = StringBuilder("Group[")
        buffer.append("groupId=")
        buffer.append(groupId)
        buffer.append(", groupIdentifier=")
        buffer.append(groupIdentifier)
        buffer.append(", epoch=")
        buffer.append(epoch)
        buffer.append(", members={")
        buffer.append(members.joinToString(", "))
        buffer.append("}, groupInfo=")
        buffer.append(groupInfo)
        buffer.append(", prevGroupStateHash=")
        buffer.append(prevGroupStateHash)
        buffer.append("]")
        buffer.toString()
    }

    override fun toString(): String = repr

    val admins: List<GroupMemberInfo> by lazy {
        members.filter { it.role == GroupMemberRole.ADMIN }
    }

    fun findMemberById(memberKeyId: SecureHash): GroupMemberInfo? {
        return members.firstOrNull { it.memberKeyId == memberKeyId }
    }

    fun findMemberByName(memberName: String): GroupMemberInfo? {
        return members.firstOrNull { it.memberName == memberName }
    }

    fun applyGroupChange(operation: GroupChange): GroupInfo {
        return when (operation) {
            is GroupMemberAdd -> applyMemberAdd(operation)
            is GroupMemberRemove -> applyMemberRemove(operation)
            is GroupMemberModify -> applyMemberModify(operation)
            is GroupModify -> applyGroupModify(operation)
            else -> throw IllegalArgumentException("unknown group operation ${operation.javaClass.name}")
        }
    }

    fun applyMemberAdd(
        add: GroupMemberAdd
    ): GroupInfo {
        add.verify(this)
        val newEpoch = epoch + 1
        val newMembersList = members + add.newInfo
        return this.copy(epoch = newEpoch, members = newMembersList, prevGroupStateHash = groupStateHash)
    }

    fun applyMemberRemove(remove: GroupMemberRemove): GroupInfo {
        remove.verify(this)
        val newEpoch = epoch + 1
        val sponsor = findMemberById(remove.sponsorKeyId)!!
        val updatedSponsor = sponsor.copy(groupDhKey = remove.newSponsorDhKey)
        val newMembersList = members.mapNotNull {
            val member = if (it.sponsor == remove.memberKeyId) {
                it.copy(sponsor = remove.sponsorKeyId)
            } else {
                it
            }
            when (member.memberKeyId) {
                remove.sponsorKeyId -> {
                    updatedSponsor
                }
                remove.memberKeyId -> {
                    null
                }
                else -> {
                    member
                }
            }
        }
        return this.copy(epoch = newEpoch, members = newMembersList, prevGroupStateHash = groupStateHash)
    }

    fun applyMemberModify(modify: GroupMemberModify): GroupInfo {
        modify.verify(this)
        val newEpoch = epoch + 1
        val newMembersList = members.map { if (it.memberName == modify.newInfo.memberName) modify.newInfo else it }
        return this.copy(epoch = newEpoch, members = newMembersList, prevGroupStateHash = groupStateHash)
    }

    fun applyGroupModify(modify: GroupModify): GroupInfo {
        modify.verify(this)
        val newEpoch = epoch + 1
        return this.copy(epoch = newEpoch, groupInfo = modify.newGroupInfo, prevGroupStateHash = groupStateHash)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupInfo

        if (groupId != other.groupId) return false
        if (groupIdentifier != other.groupIdentifier) return false
        if (epoch != other.epoch) return false
        if (members != other.members) return false
        if (groupInfo != other.groupInfo) return false
        if (prevGroupStateHash != other.prevGroupStateHash) return false

        return true
    }

    override fun hashCode(): Int {
        var result = groupId.hashCode()
        result = 31 * result + groupIdentifier.hashCode()
        result = 31 * result + epoch
        result = 31 * result + members.hashCode()
        result = 31 * result + groupInfo.hashCode()
        result = 31 * result + prevGroupStateHash.hashCode()
        return result
    }
}