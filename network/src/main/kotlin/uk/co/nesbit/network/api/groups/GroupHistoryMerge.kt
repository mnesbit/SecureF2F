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

data class GroupHistoryMerge(
    val parentStateHashes: List<SecureHash>,
    val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupHistoryMergeRecord: GenericRecord) : this(
        groupHistoryMergeRecord.getTyped("parentStateHashes"),
        groupHistoryMergeRecord.getTyped("sponsorKeyId"),
        groupHistoryMergeRecord.getTyped("sponsorSignature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupHistoryMergeSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/grouphistorymerge.avsc"))

        fun deserialize(bytes: ByteArray): GroupHistoryMerge {
            val groupHistoryMergeRecord = groupHistoryMergeSchema.deserialize(bytes)
            return GroupHistoryMerge(groupHistoryMergeRecord)
        }

        fun createGroupHistoryMerge(
            parents: List<GroupInfo>,
            sponsorKeyId: SecureHash,
            keyService: KeyService
        ): GroupHistoryMerge {
            val sharedAdmins =
                parents.map { it.admins.toSet() }.fold(emptySet<GroupMemberInfo>()) { accumulator, entries ->
                    accumulator.intersect(entries)
                }
            val sponsorInfo = sharedAdmins.firstOrNull { it.memberKeyId == sponsorKeyId }
            require(sponsorInfo != null) {
                "Sponsor not found"
            }
            require(sponsorInfo.role == GroupMemberRole.ADMIN) {
                "Sponsor not an admin"
            }
            require(parents.size > 1) {
                "Merges require at least 2 parents"
            }
            val stateHashes = parents.map { it.groupStateHash }
            val templateObject = GroupHistoryMerge(
                stateHashes,
                sponsorKeyId,
                DigitalSignature("GROUPHISTORYMERGE", ByteArray(0))
            )
            val signature = keyService.sign(sponsorKeyId, templateObject.serialize()).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }

    }

    override val groupStateHash: SecureHash
        get() = parentStateHashes.first()

    override fun toGenericRecord(): GenericRecord {
        val groupHistoryMergeRecord = GenericData.Record(groupHistoryMergeSchema)
        groupHistoryMergeRecord.putTyped("parentStateHashes", parentStateHashes)
        groupHistoryMergeRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupHistoryMergeRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupHistoryMergeRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupHistoryMerge = GroupHistoryMerge(
        parentStateHashes,
        sponsorKeyId,
        newSignature
    )

    override fun verify(groupInfo: GroupInfo) {
        val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
        require(sponsorInfo != null) {
            "Sponsor not found"
        }
        require(sponsorInfo.role == GroupMemberRole.ADMIN) {
            "Sponsor not an admin"
        }
        require(parentStateHashes.any { it == groupInfo.groupStateHash }) {
            "Group must be one of the parents"
        }
        require(parentStateHashes.size > 1) {
            "Merges require at least 2 parents"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("GROUPHISTORYMERGE", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
    }

    fun applyGroupHistoryMerge(
        groupHistory: Map<SecureHash, GroupInfo>,
        changeHistory: Map<SecureHash, GroupChange>
    ): GroupInfo {
        TODO()
    }

    override fun toString(): String =
        "GroupHistoryMerge[parentStateHashes=$parentStateHashes, groupStateHash=$groupStateHash, sponsorKeyId=$sponsorKeyId]"

}