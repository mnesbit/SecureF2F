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

class GroupMemberAddressChange private constructor(
    val memberKeyId: SecureHash,
    val oldRoutingAddress: SecureHash,
    val newRoutingAddress: SecureHash,
    val memberSignature: DigitalSignature
) : GroupChange {
    constructor(groupMemberAddressChangeRecord: GenericRecord) : this(
        groupMemberAddressChangeRecord.getTyped("memberKeyId"),
        groupMemberAddressChangeRecord.getTyped("oldRoutingAddress"),
        groupMemberAddressChangeRecord.getTyped("newRoutingAddress"),
        groupMemberAddressChangeRecord.getTyped("memberSignature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberAddressChangeSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmemberaddresschange.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberAddressChange {
            val groupMemberAddressChangeRecord = groupMemberAddressChangeSchema.deserialize(bytes)
            return GroupMemberAddressChange(groupMemberAddressChangeRecord)
        }

        fun createGroupMemberAddressChange(
            groupInfo: GroupInfo,
            memberKeyId: SecureHash,
            newAddress: SecureHash,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupMemberAddressChange {
            val memberInfo = groupInfo.findMemberById(memberKeyId)
                ?: throw java.lang.IllegalArgumentException("Member not found $memberKeyId")
            val templateObject = GroupMemberAddressChange(
                memberInfo.memberKeyId,
                memberInfo.routingAddress,
                newAddress,
                DigitalSignature("ADDRESSCHANGEREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService(memberInfo.memberKeyId, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberAddressChangeRecord = GenericData.Record(groupMemberAddressChangeSchema)
        groupMemberAddressChangeRecord.putTyped("memberKeyId", memberKeyId)
        groupMemberAddressChangeRecord.putTyped("oldRoutingAddress", oldRoutingAddress)
        groupMemberAddressChangeRecord.putTyped("newRoutingAddress", newRoutingAddress)
        groupMemberAddressChangeRecord.putTyped("memberSignature", memberSignature)
        return groupMemberAddressChangeRecord
    }

    override val sponsorKeyId: SecureHash
        get() = memberKeyId

    private fun changeSignature(newSignature: DigitalSignature): GroupMemberAddressChange = GroupMemberAddressChange(
        memberKeyId,
        oldRoutingAddress,
        newRoutingAddress,
        newSignature
    )

    override fun verify(groupInfo: GroupInfo) {
        val oldInfo = groupInfo.findMemberById(memberKeyId)
        require(oldInfo != null) {
            "Member $memberKeyId not found"
        }
        val signatureObject = this.changeSignature(DigitalSignature("ADDRESSCHANGEREQUEST", ByteArray(0))).serialize()
        memberSignature.verify(oldInfo.memberKey, signatureObject)
        require(oldInfo.routingAddress == oldRoutingAddress) {
            "Previous address ${oldInfo.routingAddress} doesn't match $oldRoutingAddress"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberAddressChange

        if (memberKeyId != other.memberKeyId) return false
        if (oldRoutingAddress != other.oldRoutingAddress) return false
        if (newRoutingAddress != other.newRoutingAddress) return false
        if (memberSignature != other.memberSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = memberKeyId.hashCode()
        result = 31 * result + oldRoutingAddress.hashCode()
        result = 31 * result + newRoutingAddress.hashCode()
        result = 31 * result + memberSignature.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberAddressChange[memberKeyId=$memberKeyId, oldRoutingAddress=$oldRoutingAddress, newRoutingAddress=$newRoutingAddress]"
}