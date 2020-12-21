package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.services.KeyService
import java.security.PublicKey

class GroupMemberRemove private constructor(
    val memberKeyId: SecureHash,
    override val groupStateHash: SecureHash,
    val newSponsorDhKey: PublicKey,
    val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupRemoveRequestRecord: GenericRecord) : this(
        groupRemoveRequestRecord.getTyped("memberKeyId"),
        groupRemoveRequestRecord.getTyped("groupStateHash"),
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
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupmemberremove.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberRemove {
            val groupRemoveRequestRecord = groupRemoveRequestSchema.deserialize(bytes)
            return GroupMemberRemove(groupRemoveRequestRecord)
        }

        fun createRemoveRequest(
            groupInfo: GroupInfo,
            memberKeyId: SecureHash,
            sponsorKeyId: SecureHash,
            newDhKeyId: SecureHash,
            keyService: KeyService
        ): GroupMemberRemove {
            require(groupInfo.members.any { it.memberKeyId == memberKeyId }) {
                "Member $memberKeyId not found"
            }
            val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
            require(sponsorInfo != null) {
                "Sponsor not found"
            }
            require(sponsorInfo.role == GroupMemberRole.ADMIN) {
                "Sponsor not an admin"
            }
            val template = GroupMemberRemove(
                memberKeyId,
                groupInfo.groupStateHash,
                keyService.getDhKey(newDhKeyId),
                sponsorKeyId,
                DigitalSignature("REMOVEREQUEST", ByteArray(0))
            )
            val signatureObject = template.serialize()
            return template.changeSignature(
                keyService.sign(sponsorInfo.memberKeyId, signatureObject).toDigitalSignature()
            )
        }
    }

    override fun verify(groupInfo: GroupInfo) {
        require(groupInfo.members.any { it.memberKeyId == memberKeyId }) {
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
        val signatureObject = this.changeSignature(
            DigitalSignature("REMOVEREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
    }

    override fun toGenericRecord(): GenericRecord {
        val groupRemoveRequestRecord = GenericData.Record(groupRemoveRequestSchema)
        groupRemoveRequestRecord.putTyped("memberKeyId", memberKeyId)
        groupRemoveRequestRecord.putTyped("groupStateHash", groupStateHash)
        groupRemoveRequestRecord.putTyped("newSponsorDhKey", newSponsorDhKey)
        groupRemoveRequestRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupRemoveRequestRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupRemoveRequestRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupMemberRemove = GroupMemberRemove(
        memberKeyId,
        groupStateHash,
        newSponsorDhKey,
        sponsorKeyId,
        newSignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberRemove

        if (memberKeyId != other.memberKeyId) return false
        if (groupStateHash != other.groupStateHash) return false
        if (newSponsorDhKey != other.newSponsorDhKey) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = memberKeyId.hashCode()
        result = 31 * result + groupStateHash.hashCode()
        result = 31 * result + newSponsorDhKey.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberRemove[memberKeyId=$memberKeyId, groupStateHash=$groupStateHash, sponsorKeyId=$sponsorKeyId]"

}