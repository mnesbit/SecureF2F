package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash

class GroupMemberAdminChange private constructor(
    val memberKeyId: SecureHash,
    val role: GroupMemberRole,
    val otherInfo: Map<String, String>,
    override val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupMemberAdminChangeRecord: GenericRecord) : this(
        groupMemberAdminChangeRecord.getTyped("memberKeyId"),
        groupMemberAdminChangeRecord.getTypedEnum("role"),
        groupMemberAdminChangeRecord.getTyped<Map<String, String>>("otherInfo").toSortedMap(),
        groupMemberAdminChangeRecord.getTyped("sponsorKeyId"),
        groupMemberAdminChangeRecord.getTyped("sponsorSignature"),
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberAdminChangeSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmemberadminchange.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberAdminChange {
            val groupMemberAdminChangeRecord = groupMemberAdminChangeSchema.deserialize(bytes)
            return GroupMemberAdminChange(groupMemberAdminChangeRecord)
        }

        fun createGroupMemberAdminChange(
            groupInfo: GroupInfo,
            memberKeyId: SecureHash,
            role: GroupMemberRole,
            otherInfo: Map<String, String>,
            sponsorKeyId: SecureHash,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupMemberAdminChange {
            val memberInfo = groupInfo.findMemberById(memberKeyId)
            require(memberInfo != null) {
                "Member $memberKeyId not found"
            }
            val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
            require(sponsorInfo != null) {
                "Sponsor not found"
            }
            require(sponsorInfo.role == GroupMemberRole.ADMIN) {
                "Sponsor not an admin"
            }
            if (role != memberInfo.role && memberInfo.role == GroupMemberRole.ADMIN) {
                require(sponsorInfo.issueEpoch < memberInfo.issueEpoch || sponsorKeyId == memberKeyId) {
                    "Cannot change the role of a more senior admin"
                }
            }
            val templateObject = GroupMemberAdminChange(
                memberKeyId,
                role,
                otherInfo,
                sponsorKeyId,
                DigitalSignature("ADMINCHANGEREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService(sponsorKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberAdminChangeRecord = GenericData.Record(groupMemberAdminChangeSchema)
        groupMemberAdminChangeRecord.putTyped("memberKeyId", memberKeyId)
        groupMemberAdminChangeRecord.putTyped("role", role)
        groupMemberAdminChangeRecord.putTyped("otherInfo", otherInfo)
        groupMemberAdminChangeRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupMemberAdminChangeRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupMemberAdminChangeRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupMemberAdminChange = GroupMemberAdminChange(
        memberKeyId,
        role,
        otherInfo,
        sponsorKeyId,
        newSignature
    )

    override fun verify(groupInfo: GroupInfo) {
        val memberInfo = groupInfo.findMemberById(memberKeyId)
        require(memberInfo != null) {
            "Member $memberKeyId not found"
        }
        val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
        require(sponsorInfo != null) {
            "Sponsor not found"
        }
        require(sponsorInfo.role == GroupMemberRole.ADMIN) {
            "Sponsor not an admin"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("ADMINCHANGEREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
        if (role != memberInfo.role && memberInfo.role == GroupMemberRole.ADMIN) {
            require(sponsorInfo.issueEpoch < memberInfo.issueEpoch || sponsorKeyId == memberKeyId) {
                "Cannot change the role of a more senior admin"
            }
        }
    }

    override fun apply(groupInfo: GroupInfo): GroupInfo {
        val newEpoch = groupInfo.epoch + 1
        val newMembers = groupInfo.members.map { member ->
            if (member.memberKeyId == memberKeyId) {
                val newSponsor = if (role != member.role) sponsorKeyId else member.sponsor
                val newMemberEpoch = if (role != member.role) newEpoch else member.issueEpoch
                member.copy(role = role, otherInfo = otherInfo, sponsor = newSponsor, issueEpoch = newMemberEpoch)
            } else {
                member
            }
        }
        return groupInfo.copy(epoch = newEpoch, members = newMembers)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberAdminChange

        if (memberKeyId != other.memberKeyId) return false
        if (role != other.role) return false
        if (otherInfo != other.otherInfo) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = memberKeyId.hashCode()
        result = 31 * result + role.hashCode()
        result = 31 * result + otherInfo.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberAdminChange[memberKeyId=$memberKeyId, role=$role, otherInfo=$otherInfo, sponsorKeyId=$sponsorKeyId]"
}