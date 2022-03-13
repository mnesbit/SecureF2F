package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.id
import uk.co.nesbit.crypto.merkle.MerkleTree
import java.security.PublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit

class GroupInfo private constructor(
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
        val EmptyGroup = GroupInfo(
            SecureHash.secureHash("EmptyGroup"),
            "",
            -1,
            emptyList(),
            emptyMap(),
            SecureHash.secureHash("EmptyGroup")
        )

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupInfoSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    GroupMemberInfo.groupMemberInfoSchema.fullName to GroupMemberInfo.groupMemberInfoSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupinfo.avsc"))

        fun deserialize(bytes: ByteArray): GroupInfo {
            val groupInfoRecord = groupInfoSchema.deserialize(bytes)
            return GroupInfo(groupInfoRecord)
        }

        fun createInitialGroup(
            groupId: SecureHash,
            groupName: String,
            groupInfo: Map<String, String>,
            initialMemberName: String,
            initialMemberKey: PublicKey,
            initialMemberDhKey: PublicKey,
            initialMemberAddress: SecureHash,
            initialMemberInfo: Map<String, String>,
            now: Instant
        ): GroupInfo {
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS)
            val initialMember = GroupMemberInfo(
                initialMemberName,
                initialMemberKey,
                truncatedNow,
                0,
                initialMemberKey.id,
                GroupMemberRole.ADMIN,
                initialMemberInfo,
                emptyList(),
                initialMemberDhKey,
                initialMemberAddress
            )
            return GroupInfo(
                groupId,
                groupName,
                0,
                listOf(initialMember),
                groupInfo,
                SecureHash.secureHash(groupId.serialize())
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

    fun copy(
        groupId: SecureHash = this.groupId,
        groupIdentifier: String = this.groupIdentifier,
        epoch: Int = this.epoch,
        members: List<GroupMemberInfo> = this.members,
        groupInfo: Map<String, String> = this.groupInfo,
        prevGroupStateHash: SecureHash = this.prevGroupStateHash
    ): GroupInfo = GroupInfo(groupId, groupIdentifier, epoch, members, groupInfo, prevGroupStateHash)

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
        operation.verify(this)
        return operation.apply(this)
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