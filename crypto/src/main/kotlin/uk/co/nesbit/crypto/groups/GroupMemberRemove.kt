package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import java.security.PublicKey

class GroupMemberRemove private constructor(
    val memberKeyId: SecureHash,
    val newSponsorDhKey: PublicKey,
    override val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupRemoveRequestRecord: GenericRecord) : this(
        groupRemoveRequestRecord.getTyped("memberKeyId"),
        groupRemoveRequestRecord.getTyped("newSponsorDhKey"),
        groupRemoveRequestRecord.getTyped("sponsorKeyId"),
        groupRemoveRequestRecord.getTyped("sponsorSignature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupRemoveRequestSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmemberremove.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberRemove {
            val groupRemoveRequestRecord = groupRemoveRequestSchema.deserialize(bytes)
            return GroupMemberRemove(groupRemoveRequestRecord)
        }

        fun createRemoveRequest(
            groupInfo: GroupInfo,
            memberKeyId: SecureHash,
            sponsorKeyId: SecureHash,
            newDhKey: PublicKey,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupMemberRemove {
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
            require(memberInfo.issueEpoch >= sponsorInfo.issueEpoch) {
                "Members can only be removed by more senior Admins"
            }
            val template = GroupMemberRemove(
                memberKeyId,
                newDhKey,
                sponsorKeyId,
                DigitalSignature("REMOVEREQUEST", ByteArray(0))
            )
            val signatureObject = template.serialize()
            return template.changeSignature(
                keyService(sponsorInfo.memberKeyId, signatureObject).toDigitalSignature()
            )
        }
    }

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
        require(groupInfo.members.count {
            it.role == GroupMemberRole.ADMIN && it.memberKeyId != memberKeyId
        } > 0) {
            "At least one Admin must remain"
        }
        require(memberInfo.role != GroupMemberRole.ADMIN || memberInfo.issueEpoch >= sponsorInfo.issueEpoch) {
            "Admins can only be removed by more senior Admins"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("REMOVEREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
    }

    override fun toGenericRecord(): GenericRecord {
        val groupRemoveRequestRecord = GenericData.Record(groupRemoveRequestSchema)
        groupRemoveRequestRecord.putTyped("memberKeyId", memberKeyId)
        groupRemoveRequestRecord.putTyped("newSponsorDhKey", newSponsorDhKey)
        groupRemoveRequestRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupRemoveRequestRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupRemoveRequestRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupMemberRemove = GroupMemberRemove(
        memberKeyId,
        newSponsorDhKey,
        sponsorKeyId,
        newSignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberRemove

        if (memberKeyId != other.memberKeyId) return false
        if (newSponsorDhKey != other.newSponsorDhKey) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = memberKeyId.hashCode()
        result = 31 * result + newSponsorDhKey.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberRemove[memberKeyId=$memberKeyId, sponsorKeyId=$sponsorKeyId]"

}