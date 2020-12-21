package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.services.KeyService

class GroupModify(
    val newGroupInfo: Map<String, String>,
    override val groupStateHash: SecureHash,
    val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupModifyRecord: GenericRecord) : this(
        groupModifyRecord.getTyped("newGroupInfo"),
        groupModifyRecord.getTyped("groupStateHash"),
        groupModifyRecord.getTyped("sponsorKeyId"),
        groupModifyRecord.getTyped("sponsorSignature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupModifySchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupmodify.avsc"))

        fun deserialize(bytes: ByteArray): GroupModify {
            val groupModifyRecord = groupModifySchema.deserialize(bytes)
            return GroupModify(groupModifyRecord)
        }

        fun createModify(
            groupInfo: GroupInfo,
            newInfo: Map<String, String>,
            sponsorKeyId: SecureHash,
            keyService: KeyService
        ): GroupModify {
            val templateObject = GroupModify(
                newInfo,
                groupInfo.groupStateHash,
                sponsorKeyId,
                DigitalSignature("MODIFYREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService.sign(sponsorKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }

    }

    override fun toGenericRecord(): GenericRecord {
        val groupModifyRecord = GenericData.Record(groupModifySchema)
        groupModifyRecord.putTyped("newGroupInfo", newGroupInfo)
        groupModifyRecord.putTyped("groupStateHash", groupStateHash)
        groupModifyRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupModifyRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupModifyRecord
    }

    override fun verify(groupInfo: GroupInfo) {
        require(groupInfo.groupStateHash == groupStateHash) {
            "Change being applied to mismatched group state"
        }
        val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
        require(sponsorInfo != null) {
            "Sponsor not found"
        }
        require(sponsorInfo.role == GroupMemberRole.ADMIN) {
            "Sponsor not an admin"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("MODIFYREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupModify = GroupModify(
        newGroupInfo,
        groupStateHash,
        sponsorKeyId,
        newSignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupModify

        if (newGroupInfo != other.newGroupInfo) return false
        if (groupStateHash != other.groupStateHash) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = newGroupInfo.hashCode()
        result = 31 * result + groupStateHash.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupModify[newGroupInfo=$newGroupInfo, groupStateHash=$groupStateHash, sponsorKeyId=$sponsorKeyId]"

}