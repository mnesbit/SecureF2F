package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash

class GroupMerge(
    val previousGroupInfoHashes: List<SecureHash>,
    override val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupMergeRecord: GenericRecord) : this(
        groupMergeRecord.getObjectArray("previousGroupInfoHashes", ::SecureHash),
        groupMergeRecord.getTyped("sponsorKeyId"),
        groupMergeRecord.getTyped("sponsorSignature")
    )

    init {
        require(previousGroupInfoHashes.size > 1) {
            "Merge requires at least two predecessor chains $previousGroupInfoHashes"
        }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMergeSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmerge.avsc"))

        fun deserialize(bytes: ByteArray): GroupMerge {
            val groupMergeRecord = groupMergeSchema.deserialize(bytes)
            return GroupMerge(groupMergeRecord)
        }

        fun createGroupMerge(
            previousGroupInfoHashes: List<SecureHash>,
            sponsorId: SecureHash,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupMerge {
            val templateObject = GroupMerge(
                previousGroupInfoHashes,
                sponsorId,
                DigitalSignature("MERGEREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService(sponsorId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupMerge = GroupMerge(
        previousGroupInfoHashes,
        sponsorKeyId,
        newSignature
    )

    override fun toGenericRecord(): GenericRecord {
        val groupMemberAddRecord = GenericData.Record(groupMergeSchema)
        groupMemberAddRecord.putObjectArray("previousGroupInfoHashes", previousGroupInfoHashes)
        groupMemberAddRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupMemberAddRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupMemberAddRecord
    }

    override fun verify(groupInfo: GroupInfo) {
        val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
        require(sponsorInfo != null) {
            "Sponsor not found"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("MERGEREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMerge

        if (previousGroupInfoHashes != other.previousGroupInfoHashes) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = previousGroupInfoHashes.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMerge[previousGroupInfoHashes=$previousGroupInfoHashes, sponsorKeyId=$sponsorKeyId]"

}