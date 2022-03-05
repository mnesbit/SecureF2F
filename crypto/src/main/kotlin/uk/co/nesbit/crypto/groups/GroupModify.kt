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
import uk.co.nesbit.crypto.SecureHash

class GroupModify(
    val newGroupInfo: Map<String, String>,
    override val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupModifyRecord: GenericRecord) : this(
        groupModifyRecord.getTyped("newGroupInfo"),
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
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmodify.avsc"))

        fun deserialize(bytes: ByteArray): GroupModify {
            val groupModifyRecord = groupModifySchema.deserialize(bytes)
            return GroupModify(groupModifyRecord)
        }

        fun createModify(
            newInfo: Map<String, String>,
            sponsorKeyId: SecureHash,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupModify {
            val templateObject = GroupModify(
                newInfo,
                sponsorKeyId,
                DigitalSignature("MODIFYREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService(sponsorKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }

    }

    override fun toGenericRecord(): GenericRecord {
        val groupModifyRecord = GenericData.Record(groupModifySchema)
        groupModifyRecord.putTyped("newGroupInfo", newGroupInfo)
        groupModifyRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupModifyRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupModifyRecord
    }

    override fun verify(groupInfo: GroupInfo) {
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
        sponsorKeyId,
        newSignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupModify

        if (newGroupInfo != other.newGroupInfo) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = newGroupInfo.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupModify[newGroupInfo=$newGroupInfo, sponsorKeyId=$sponsorKeyId]"

}