package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.*
import java.security.PublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit

class GroupMemberKeyRotate private constructor(
    val memberKeyId: SecureHash,
    val keyIssueTime: Instant,
    val rotateMemberKey: Boolean,
    val oldKeyHash: SecureHash,
    val newKey: PublicKey,
    val memberSignatures: List<DigitalSignature>
) : GroupChange {

    constructor(groupMemberKeyRotateRecord: GenericRecord) : this(
        groupMemberKeyRotateRecord.getTyped("memberKeyId"),
        groupMemberKeyRotateRecord.getTyped("keyIssueTime"),
        groupMemberKeyRotateRecord.getTyped("rotateMemberKey"),
        groupMemberKeyRotateRecord.getTyped("oldKeyHash"),
        groupMemberKeyRotateRecord.getTyped("newKey"),
        groupMemberKeyRotateRecord.getObjectArray("memberSignatures", ::DigitalSignature)
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberKeyRotateSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmemberkeyrotate.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberKeyRotate {
            val groupMemberKeyRotateRecord = groupMemberKeyRotateSchema.deserialize(bytes)
            return GroupMemberKeyRotate(groupMemberKeyRotateRecord)
        }

        fun createGroupMemberKeyRotate(
            groupInfo: GroupInfo,
            memberKeyId: SecureHash,
            rotateMemberKey: Boolean,
            newKey: PublicKey,
            now: Instant,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupMemberKeyRotate {
            val memberInfo = groupInfo.findMemberById(memberKeyId)
                ?: throw java.lang.IllegalArgumentException("Member not found $memberKeyId")
            require(groupInfo.members.none { member ->
                member.memberKey == newKey
                        || member.groupDhKey == newKey
                        || member.historicKeys.any { entry -> entry.key == newKey }
            }) {
                "Key cannot be rotated to existing key"
            }
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            require(truncatedNow.isAfter(memberInfo.keyIssued)) {
                "Rotation time $truncatedNow not after old issue time ${memberInfo.keyIssued}"
            }
            val oldKey = if (rotateMemberKey) memberInfo.memberKey else memberInfo.groupDhKey
            val oldKeyHash = oldKey.id
            val templateObject = GroupMemberKeyRotate(
                memberInfo.memberKeyId,
                truncatedNow,
                rotateMemberKey,
                oldKeyHash,
                newKey,
                listOf(DigitalSignature("ROTATEREQUEST", ByteArray(0)))
            )
            val signatureBytes = templateObject.serialize()
            val signatures = mutableListOf<DigitalSignature>()
            signatures += keyService(memberInfo.memberKeyId, signatureBytes).toDigitalSignature()
            if (rotateMemberKey) {
                signatures += keyService(newKey.id, signatureBytes).toDigitalSignature()
            }
            return templateObject.changeSignatures(signatures)
        }
    }

    private fun changeSignatures(newSignature: List<DigitalSignature>): GroupMemberKeyRotate = GroupMemberKeyRotate(
        memberKeyId,
        keyIssueTime,
        rotateMemberKey,
        oldKeyHash,
        newKey,
        newSignature
    )

    override fun toGenericRecord(): GenericRecord {
        val groupMemberKeyRotateRecord = GenericData.Record(groupMemberKeyRotateSchema)
        groupMemberKeyRotateRecord.putTyped("memberKeyId", memberKeyId)
        groupMemberKeyRotateRecord.putTyped("keyIssueTime", keyIssueTime)
        groupMemberKeyRotateRecord.putTyped("rotateMemberKey", rotateMemberKey)
        groupMemberKeyRotateRecord.putTyped("oldKeyHash", oldKeyHash)
        groupMemberKeyRotateRecord.putTyped("newKey", newKey)
        groupMemberKeyRotateRecord.putObjectArray("memberSignatures", memberSignatures)
        return groupMemberKeyRotateRecord
    }

    override val sponsorKeyId: SecureHash
        get() = if (rotateMemberKey) newKey.id else memberKeyId

    override fun verify(groupInfo: GroupInfo) {
        val oldInfo = groupInfo.findMemberById(memberKeyId)
        require(oldInfo != null) {
            "Member $memberKeyId not found"
        }
        val signatureObject = this.changeSignatures(listOf(DigitalSignature("ROTATEREQUEST", ByteArray(0)))).serialize()
        if (rotateMemberKey) {
            require(memberSignatures.size == 2) {
                "Incorrect number of member signatures"
            }
            memberSignatures[0].verify(oldInfo.memberKey, signatureObject)
            memberSignatures[1].verify(newKey, signatureObject)
            require(oldKeyHash == oldInfo.memberKeyId) {
                "previous key does not correct"
            }
        } else {
            require(memberSignatures.size == 1) {
                "Incorrect number of member signatures"
            }
            memberSignatures.single().verify(oldInfo.memberKey, signatureObject)
            require(oldKeyHash == oldInfo.groupDhKey.id) {
                "previous key does not correct"
            }
        }
        require(groupInfo.members.none { member ->
            member.memberKey == newKey
                    || member.groupDhKey == newKey
                    || member.historicKeys.any { entry -> entry.key == newKey }
        }) {
            "Key cannot be rotated to existing key"
        }
        require(keyIssueTime.isAfter(oldInfo.keyIssued)) {
            "Rotation time $keyIssueTime not after old issue time ${oldInfo.keyIssued}"
        }
    }

    override fun apply(groupInfo: GroupInfo): GroupInfo {
        val newEpoch = groupInfo.epoch + 1
        val newMembers = groupInfo.members.map { member ->
            if (member.memberKeyId == memberKeyId) {
                if (rotateMemberKey) {
                    val newKeyHistory =
                        member.historicKeys + HistoricKeyInfo(member.memberKey, member.keyIssued, keyIssueTime)
                    member.copy(
                        memberKey = newKey,
                        keyIssued = keyIssueTime,
                        historicKeys = newKeyHistory
                    )
                } else {
                    member.copy(groupDhKey = newKey)
                }
            } else {
                member
            }
        }
        return groupInfo.copy(epoch = newEpoch, members = newMembers)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberKeyRotate

        if (memberKeyId != other.memberKeyId) return false
        if (keyIssueTime != other.keyIssueTime) return false
        if (rotateMemberKey != other.rotateMemberKey) return false
        if (oldKeyHash != other.oldKeyHash) return false
        if (newKey != other.newKey) return false
        if (memberSignatures != other.memberSignatures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = memberKeyId.hashCode()
        result = 31 * result + keyIssueTime.hashCode()
        result = 31 * result + rotateMemberKey.hashCode()
        result = 31 * result + oldKeyHash.hashCode()
        result = 31 * result + newKey.hashCode()
        result = 31 * result + memberSignatures.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberKeyRotate[memberKeyId=$memberKeyId, rotateMemberKey=$rotateMemberKey, oldKey=$oldKeyHash, newKey=${newKey.id} ]"
}