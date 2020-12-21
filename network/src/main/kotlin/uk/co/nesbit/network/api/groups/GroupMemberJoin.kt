package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.services.KeyService
import java.security.PublicKey
import java.security.SignatureException

class GroupMemberJoin private constructor(
    val invite: GroupInviteToken,
    val memberName: String,
    val memberKey: PublicKey,
    val routingAddress: VersionedIdentity,
    val groupDhKey: PublicKey,
    val signatures: List<DigitalSignatureAndKey>
) : GroupMessage {
    constructor(groupMemberJoinRecord: GenericRecord) : this(
        groupMemberJoinRecord.getTyped("invite"),
        groupMemberJoinRecord.getTyped("memberName"),
        groupMemberJoinRecord.getTyped("memberKey"),
        groupMemberJoinRecord.getTyped("routingAddress"),
        groupMemberJoinRecord.getTyped("groupDhKey"),
        groupMemberJoinRecord.getObjectArray("signatures", ::DigitalSignatureAndKey)
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberJoinSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    DigitalSignatureAndKey.digitalSignatureAndKeySchema.fullName to DigitalSignatureAndKey.digitalSignatureAndKeySchema,
                    VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                    GroupInviteToken.groupInviteTokenSchema.fullName to GroupInviteToken.groupInviteTokenSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupmemberjoin.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberJoin {
            val groupMemberJoinRecord = groupMemberJoinSchema.deserialize(bytes)
            return GroupMemberJoin(groupMemberJoinRecord)
        }

        fun createJoinRequest(
            invite: GroupInviteToken,
            memberName: String,
            groupKeyId: SecureHash,
            networkAddressId: SecureHash,
            keyService: KeyService
        ): GroupMemberJoin {
            val dhKey = keyService.generateDhKey()
            val templateObject = GroupMemberJoin(
                invite,
                memberName,
                keyService.getSigningKey(groupKeyId),
                keyService.getVersion(networkAddressId),
                keyService.getDhKey(dhKey),
                emptyList()
            )
            val signatureBytes = templateObject.serialize()
            val signatures = mutableListOf<DigitalSignatureAndKey>()
            signatures += keyService.sign(groupKeyId, signatureBytes)
            signatures += keyService.sign(networkAddressId, signatureBytes)
            return templateObject.changeSignatures(signatures)
        }
    }

    fun verify(group: GroupInfo) {
        val sponsor = group.findMemberById(invite.sponsorKeyId)
        require(sponsor != null) {
            "Sponsor not found"
        }
        require(sponsor.role == GroupMemberRole.ADMIN) {
            "Sponsor not an ADMIN"
        }
        require(sponsor.routingAddress == invite.sponsorAddress) {
            "Mismatched sponsor routing information"
        }
        if (signatures.size != 2) {
            throw SignatureException("Incorrect signatures")
        }
        val memberSignature = signatures.firstOrNull { it.publicKey == memberKey }
            ?: throw SignatureException("Member signature missing")
        val networkSignature = signatures.firstOrNull { it.publicKey == routingAddress.identity.signingPublicKey }
            ?: throw SignatureException("Network signature missing")
        val verifyItem = this.changeSignatures(emptyList()).serialize()
        memberSignature.verify(verifyItem)
        networkSignature.verify(verifyItem)

        if (invite.groupId != group.groupId
            || invite.groupIdentifier != group.groupIdentifier
            || invite.groupStateHash != group.groupStateHash
        ) {
            throw IllegalArgumentException("Invite invalid for specified group")
        }
        require(group.members.none { it.memberName == memberName }) {
            "Cannot add duplicate name"
        }
        require(group.members.none {
            it.memberKey == memberKey
                    || it.routingAddress == routingAddress.id
                    || it.groupDhKey == groupDhKey
        }) {
            "Cannot add duplicate key"
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberJoinRecord = GenericData.Record(groupMemberJoinSchema)
        groupMemberJoinRecord.putTyped("invite", invite)
        groupMemberJoinRecord.putTyped("memberName", memberName)
        groupMemberJoinRecord.putTyped("memberKey", memberKey)
        groupMemberJoinRecord.putTyped("routingAddress", routingAddress)
        groupMemberJoinRecord.putTyped("groupDhKey", groupDhKey)
        groupMemberJoinRecord.putObjectArray("signatures", signatures)
        return groupMemberJoinRecord
    }

    private fun changeSignatures(
        newSignatures: List<DigitalSignatureAndKey>
    ): GroupMemberJoin = GroupMemberJoin(
        invite,
        memberName,
        memberKey,
        routingAddress,
        groupDhKey,
        newSignatures
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberJoin

        if (invite != other.invite) return false
        if (memberName != other.memberName) return false
        if (memberKey != other.memberKey) return false
        if (routingAddress != other.routingAddress) return false
        if (groupDhKey != other.groupDhKey) return false
        if (signatures != other.signatures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = invite.hashCode()
        result = 31 * result + memberName.hashCode()
        result = 31 * result + memberKey.hashCode()
        result = 31 * result + routingAddress.hashCode()
        result = 31 * result + groupDhKey.hashCode()
        result = 31 * result + signatures.hashCode()
        return result
    }

    private val repr: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val buffer = StringBuilder("GroupMemberJoin[")
        buffer.append("memberName=")
        buffer.append(memberName)
        buffer.append(", groupId=")
        buffer.append(invite.groupId)
        buffer.append(", groupIdentifiedr=")
        buffer.append(invite.groupIdentifier)
        buffer.append(", sponsorId=")
        buffer.append(invite.sponsorKeyId)
        buffer.append("]")
        buffer.toString()
    }

    override fun toString(): String = repr
}