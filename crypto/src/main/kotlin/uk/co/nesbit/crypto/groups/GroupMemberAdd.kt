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
import java.security.PublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit

class GroupMemberAdd(
    val newInfo: GroupMemberInfo,
    override val sponsorKeyId: SecureHash,
    val sponsorSignature: DigitalSignature
) : GroupChange {
    constructor(groupMemberAddRecord: GenericRecord) : this(
        groupMemberAddRecord.getTyped("newInfo"),
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
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmemberadd.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberAdd {
            val groupMemberAddRecord = groupMemberAddSchema.deserialize(bytes)
            return GroupMemberAdd(groupMemberAddRecord)
        }

        fun createMemberAdd(
            groupInfo: GroupInfo,
            newMemberName: String,
            newMemberKey: PublicKey,
            newMemberDhKey: PublicKey,
            newMemberAddress: SecureHash,
            sponsorKeyId: SecureHash,
            now: Instant,
            startingRole: GroupMemberRole,
            startingInfo: Map<String, String>,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupMemberAdd {
            val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
            require(sponsorInfo != null) {
                "Sponsor not found"
            }
            require(sponsorInfo.role == GroupMemberRole.ADMIN) {
                "Sponsor not an admin"
            }
            val truncatedNow = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val newEpoch =
                groupInfo.epoch + 1 // we actually ignore epoch due to merges shifting them, but set a sensible value
            val newMember = GroupMemberInfo(
                newMemberName,
                newMemberKey,
                truncatedNow,
                newEpoch,
                sponsorKeyId,
                startingRole,
                startingInfo,
                emptyList(),
                newMemberDhKey,
                newMemberAddress
            )
            val templateObject = GroupMemberAdd(
                newMember,
                sponsorKeyId,
                DigitalSignature("ADDREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService(sponsorKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }

    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberAddRecord = GenericData.Record(groupMemberAddSchema)
        groupMemberAddRecord.putTyped("newInfo", newInfo)
        groupMemberAddRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupMemberAddRecord.putTyped("sponsorSignature", sponsorSignature)
        return groupMemberAddRecord
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
            DigitalSignature("ADDREQUEST", ByteArray(0))
        ).serialize()
        sponsorSignature.verify(sponsorInfo.memberKey, signatureObject)
        require(groupInfo.members.none { it.memberName == newInfo.memberName }) {
            "Cannot add duplicate name"
        }
        require(groupInfo.members.none {
            it.memberKey == newInfo.memberKey
                    || it.historicKeys.any { it.key == newInfo.memberKey }
                    || it.routingAddress == newInfo.routingAddress
                    || it.groupDhKey == newInfo.groupDhKey
        }) {
            "Cannot add duplicate key"
        }
        require(newInfo.historicKeys.isEmpty()) {
            "Initial historic keys must be empty"
        }
    }

    override fun apply(groupInfo: GroupInfo): GroupInfo {
        val newEpoch = groupInfo.epoch + 1
        val newMembersList = groupInfo.members + newInfo.copy(issueEpoch = newEpoch)
        return groupInfo.copy(epoch = newEpoch, members = newMembersList, prevGroupStateHash = groupInfo.groupStateHash)
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupMemberAdd = GroupMemberAdd(
        newInfo,
        sponsorKeyId,
        newSignature
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberAdd

        if (newInfo != other.newInfo) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorSignature != other.sponsorSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = newInfo.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberAdd[newInfo=$newInfo, sponsorKeyId=$sponsorKeyId]"
}