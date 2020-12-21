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
import java.time.Instant
import java.time.temporal.ChronoUnit

class GroupMemberAdd(
    val newInfo: GroupMemberInfo,
    override val groupStateHash: SecureHash,
    val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupMemberAddRecord: GenericRecord) : this(
        groupMemberAddRecord.getTyped("newInfo"),
        groupMemberAddRecord.getTyped("groupStateHash"),
        groupMemberAddRecord.getTyped("sponsorKeyId"),
        groupMemberAddRecord.getTyped("sponsorSignature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberAddSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    GroupMemberInfo.groupMemberInfoSchema.fullName to GroupMemberInfo.groupMemberInfoSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupmemberadd.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberAdd {
            val groupMemberAddRecord = groupMemberAddSchema.deserialize(bytes)
            return GroupMemberAdd(groupMemberAddRecord)
        }

        fun createMemberAdd(
            groupInfo: GroupInfo,
            join: GroupMemberJoin,
            now: Instant,
            startingRole: GroupMemberRole,
            startingInfo: Map<String, String>,
            keyService: KeyService
        ): GroupMemberAdd {
            join.verify(groupInfo)
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val newEpoch = groupInfo.epoch + 1
            val newMember = GroupMemberInfo(
                join.memberName,
                join.memberKey,
                truncatedNow,
                newEpoch,
                join.invite.sponsorKeyId,
                startingRole,
                startingInfo,
                emptyList(),
                join.groupDhKey,
                join.routingAddress.id
            )
            val templateObject = GroupMemberAdd(
                newMember,
                groupInfo.groupStateHash,
                join.invite.sponsorKeyId,
                DigitalSignature("ADDREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService.sign(join.invite.sponsorKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }

    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberAddRecord = GenericData.Record(groupMemberAddSchema)
        groupMemberAddRecord.putTyped("newInfo", newInfo)
        groupMemberAddRecord.putTyped("groupStateHash", groupStateHash)
        groupMemberAddRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupMemberAddRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupMemberAddRecord
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
            DigitalSignature("ADDREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
        require(groupInfo.members.none { it.memberName == newInfo.memberName }) {
            "Cannot add duplicate name"
        }
        require(groupInfo.members.none {
            it.memberKey == newInfo.memberKey
                    || it.routingAddress == newInfo.routingAddress
                    || it.groupDhKey == newInfo.groupDhKey
        }) {
            "Cannot add duplicate key"
        }
        require(groupInfo.epoch + 1 == newInfo.issueEpoch) {
            "Member issueEpoch incorrect"
        }
        require(newInfo.historicKeys.isEmpty()) {
            "Initial historic keys must be empty"
        }
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupMemberAdd = GroupMemberAdd(
        newInfo,
        groupStateHash,
        sponsorKeyId,
        newSignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberAdd

        if (newInfo != other.newInfo) return false
        if (groupStateHash != other.groupStateHash) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = newInfo.hashCode()
        result = 31 * result + groupStateHash.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberAdd[newInfo=$newInfo, groupStateHash=$groupStateHash, sponsorKeyId=$sponsorKeyId]"
}