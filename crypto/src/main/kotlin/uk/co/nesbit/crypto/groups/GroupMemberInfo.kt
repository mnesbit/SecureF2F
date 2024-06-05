package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.id
import java.security.PublicKey
import java.time.Instant

enum class GroupMemberRole {
    ADMIN,
    ORDINARY
}

data class GroupMemberInfo(
    val memberName: String,
    val memberKey: PublicKey,
    val keyIssued: Instant,
    val issueEpoch: Int,
    val sponsor: SecureHash,
    val role: GroupMemberRole,
    val otherInfo: Map<String, String>,
    val historicKeys: List<HistoricKeyInfo>,
    val groupDhKey: PublicKey,
    val routingAddress: SecureHash
) : AvroConvertible {
    constructor(groupMemberInfoRecord: GenericRecord) : this(
        groupMemberInfoRecord.getTyped("memberName"),
        groupMemberInfoRecord.getTyped("memberKey"),
        groupMemberInfoRecord.getTyped("keyIssued"),
        groupMemberInfoRecord.getTyped("issueEpoch"),
        groupMemberInfoRecord.getTyped("sponsor"),
        groupMemberInfoRecord.getTypedEnum("role"),
        groupMemberInfoRecord.getTyped<Map<String, String>>("otherInfo").toSortedMap(),
        groupMemberInfoRecord.getObjectArray("historicKeys", ::HistoricKeyInfo),
        groupMemberInfoRecord.getTyped("groupDhKey"),
        groupMemberInfoRecord.getTyped("routingAddress")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberInfoSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    HistoricKeyInfo.historicKeyInfoSchema.fullName to HistoricKeyInfo.historicKeyInfoSchema,
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupmemberinfo.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberInfo {
            val groupMemberInfoRecord = groupMemberInfoSchema.deserialize(bytes)
            return GroupMemberInfo(groupMemberInfoRecord)
        }
    }

    val memberKeyId: SecureHash by lazy {
        memberKey.id
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberInfoRecord = GenericData.Record(groupMemberInfoSchema)
        groupMemberInfoRecord.putTyped("memberName", memberName)
        groupMemberInfoRecord.putTyped("memberKey", memberKey)
        groupMemberInfoRecord.putTyped("keyIssued", keyIssued)
        groupMemberInfoRecord.putTyped("issueEpoch", issueEpoch)
        groupMemberInfoRecord.putTyped("sponsor", sponsor)
        groupMemberInfoRecord.putTyped("role", role)
        groupMemberInfoRecord.putTyped("otherInfo", otherInfo.toSortedMap())
        groupMemberInfoRecord.putObjectArray("historicKeys", historicKeys)
        groupMemberInfoRecord.putTyped("groupDhKey", groupDhKey)
        groupMemberInfoRecord.putTyped("routingAddress", routingAddress)
        return groupMemberInfoRecord
    }

    private val repr: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val buffer = StringBuilder("GroupMember[")
        buffer.append("memberName=")
        buffer.append(memberName)
        buffer.append(", memberKeyId=")
        buffer.append(memberKeyId)
        buffer.append(", keyIssued=")
        buffer.append(keyIssued)
        buffer.append(", issueEpoch=")
        buffer.append(issueEpoch)
        buffer.append(", sponsor=")
        buffer.append(sponsor)
        buffer.append(", role=")
        buffer.append(role)
        buffer.append(", otherInfo=")
        buffer.append(otherInfo)
        buffer.append(", historicKeys={")
        buffer.append(historicKeys.joinToString(", ") { "key=${it.keyId}, ${it.validFrom}-${it.validUntil}" })
        buffer.append("}, groupDhKey=")
        buffer.append(groupDhKey)
        buffer.append(", routingAddress=")
        buffer.append(routingAddress)
        buffer.append("]")
        buffer.toString()
    }

    override fun toString(): String = repr

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberInfo

        if (memberName != other.memberName) return false
        if (memberKey != other.memberKey) return false
        if (keyIssued != other.keyIssued) return false
        if (issueEpoch != other.issueEpoch) return false
        if (sponsor != other.sponsor) return false
        if (role != other.role) return false
        if (otherInfo != other.otherInfo) return false
        if (historicKeys != other.historicKeys) return false
        if (groupDhKey != other.groupDhKey) return false
        if (routingAddress != other.routingAddress) return false

        return true
    }

    override fun hashCode(): Int {
        var result = memberName.hashCode()
        result = 31 * result + memberKey.hashCode()
        result = 31 * result + keyIssued.hashCode()
        result = 31 * result + issueEpoch
        result = 31 * result + sponsor.hashCode()
        result = 31 * result + role.hashCode()
        result = 31 * result + otherInfo.hashCode()
        result = 31 * result + historicKeys.hashCode()
        result = 31 * result + groupDhKey.hashCode()
        result = 31 * result + routingAddress.hashCode()
        return result
    }

}