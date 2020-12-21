package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.services.KeyService
import java.security.PublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit

class GroupInviteToken private constructor(
    val groupIdentifier: String,
    val groupId: SecureHash,
    val groupStateHash: SecureHash,
    val inviteId: SecureHash,
    val sponsorKeyId: SecureHash,
    val sponsorAddress: SecureHash,
    val oneTimeDhKey: PublicKey,
    val expireTime: Instant
) : AvroConvertible {
    constructor(groupInviteTokenRecord: GenericRecord) : this(
        groupInviteTokenRecord.getTyped("groupIdentifier"),
        groupInviteTokenRecord.getTyped("groupId"),
        groupInviteTokenRecord.getTyped("groupStateHash"),
        groupInviteTokenRecord.getTyped("inviteId"),
        groupInviteTokenRecord.getTyped("sponsorKeyId"),
        groupInviteTokenRecord.getTyped("sponsorAddress"),
        groupInviteTokenRecord.getTyped("oneTimeDhKey"),
        groupInviteTokenRecord.getTyped("expireTime")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupInviteTokenSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupinvitetoken.avsc"))

        fun deserialize(bytes: ByteArray): GroupInviteToken {
            val groupInviteTokenRecord = groupInviteTokenSchema.deserialize(bytes)
            return GroupInviteToken(groupInviteTokenRecord)
        }

        fun deserializedJSON(json: String): GroupInviteToken {
            val groupInviteTokenRecord = groupInviteTokenSchema.deserializeJSON(json)
            return GroupInviteToken(groupInviteTokenRecord)
        }

        fun createInvite(
            group: GroupInfo,
            expireTime: Instant,
            sponsorKeyId: SecureHash,
            keyService: KeyService
        ): GroupInviteToken {
            val sponsor = group.findMemberById(sponsorKeyId)
            require(sponsor != null) {
                "Sponsor not found"
            }
            require(sponsor.role == GroupMemberRole.ADMIN) {
                "Only ADMIN role can create invites"
            }
            val truncatedExpiry = expireTime.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val bytes = ByteArray(16)
            keyService.random.nextBytes(bytes)
            val dhKey = keyService.generateDhKey()
            return GroupInviteToken(
                group.groupIdentifier,
                group.groupId,
                group.groupStateHash,
                SecureHash.secureHash(bytes),
                sponsorKeyId,
                sponsor.routingAddress,
                keyService.getDhKey(dhKey),
                truncatedExpiry
            )
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupInviteTokenRecord = GenericData.Record(groupInviteTokenSchema)
        groupInviteTokenRecord.putTyped("groupIdentifier", groupIdentifier)
        groupInviteTokenRecord.putTyped("groupId", groupId)
        groupInviteTokenRecord.putTyped("groupStateHash", groupStateHash)
        groupInviteTokenRecord.putTyped("inviteId", inviteId)
        groupInviteTokenRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupInviteTokenRecord.putTyped("sponsorAddress", sponsorAddress)
        groupInviteTokenRecord.putTyped("oneTimeDhKey", oneTimeDhKey)
        groupInviteTokenRecord.putTyped("expireTime", expireTime)
        return groupInviteTokenRecord
    }

    fun toJSON(): String = toGenericRecord().serializeJSON()
    override fun toString(): String = toJSON()
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupInviteToken

        if (groupIdentifier != other.groupIdentifier) return false
        if (groupId != other.groupId) return false
        if (groupStateHash != other.groupStateHash) return false
        if (inviteId != other.inviteId) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (sponsorAddress != other.sponsorAddress) return false
        if (oneTimeDhKey != other.oneTimeDhKey) return false
        if (expireTime != other.expireTime) return false

        return true
    }

    override fun hashCode(): Int {
        var result = groupIdentifier.hashCode()
        result = 31 * result + groupId.hashCode()
        result = 31 * result + groupStateHash.hashCode()
        result = 31 * result + inviteId.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + sponsorAddress.hashCode()
        result = 31 * result + oneTimeDhKey.hashCode()
        result = 31 * result + expireTime.hashCode()
        return result
    }


}