package uk.co.nesbit.crypto.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.*
import java.security.PublicKey
import java.time.Instant

class GroupCreate private constructor(
    val groupId: SecureHash,
    val groupIdentifier: String,
    val groupInfo: Map<String, String>,
    val initialMemberName: String,
    val initialMemberKey: PublicKey,
    val initialMemberDhKey: PublicKey,
    val initialMemberAddress: SecureHash,
    val initialMemberInfo: Map<String, String>,
    val createTime: Instant,
    val founderSignature: DigitalSignature
) : GroupChange {
    constructor(groupCreateRecord: GenericRecord) : this(
        groupCreateRecord.getTyped("groupId"),
        groupCreateRecord.getTyped("groupIdentifier"),
        groupCreateRecord.getTyped<Map<String, String>>("groupInfo").toSortedMap(),
        groupCreateRecord.getTyped("initialMemberName"),
        groupCreateRecord.getTyped("initialMemberKey"),
        groupCreateRecord.getTyped("initialMemberDhKey"),
        groupCreateRecord.getTyped("initialMemberAddress"),
        groupCreateRecord.getTyped<Map<String, String>>("initialMemberInfo").toSortedMap(),
        groupCreateRecord.getTyped("createTime"),
        groupCreateRecord.getTyped("founderSignature")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupCreateSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/groups/groupcreate.avsc"))

        fun deserialize(bytes: ByteArray): GroupCreate {
            val groupCreateRecord = groupCreateSchema.deserialize(bytes)
            return GroupCreate(groupCreateRecord)
        }

        fun createGroupCreate(
            groupId: SecureHash,
            groupIdentifier: String,
            groupInfo: Map<String, String>,
            initialMemberName: String,
            initialMemberKey: PublicKey,
            initialMemberDhKey: PublicKey,
            initialMemberAddress: SecureHash,
            initialMemberInfo: Map<String, String>,
            createTime: Instant,
            keyService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): GroupCreate {
            val templateObject = GroupCreate(
                groupId,
                groupIdentifier,
                groupInfo,
                initialMemberName,
                initialMemberKey,
                initialMemberDhKey,
                initialMemberAddress,
                initialMemberInfo,
                createTime,
                DigitalSignature("CREATEGROUPREQUEST", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = keyService(initialMemberKey.id, signatureBytes).toDigitalSignature()
            return templateObject.changeSignature(signature)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupCreateRecord = GenericData.Record(groupCreateSchema)
        groupCreateRecord.putTyped("groupId", groupId)
        groupCreateRecord.putTyped("groupIdentifier", groupIdentifier)
        groupCreateRecord.putTyped("groupInfo", groupInfo.toSortedMap())
        groupCreateRecord.putTyped("initialMemberName", initialMemberName)
        groupCreateRecord.putTyped("initialMemberKey", initialMemberKey)
        groupCreateRecord.putTyped("initialMemberDhKey", initialMemberDhKey)
        groupCreateRecord.putTyped("initialMemberAddress", initialMemberAddress)
        groupCreateRecord.putTyped("initialMemberInfo", initialMemberInfo.toSortedMap())
        groupCreateRecord.putTyped("createTime", createTime)
        groupCreateRecord.putTyped("founderSignature", founderSignature)
        return groupCreateRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): GroupCreate = GroupCreate(
        groupId,
        groupIdentifier,
        groupInfo,
        initialMemberName,
        initialMemberKey,
        initialMemberDhKey,
        initialMemberAddress,
        initialMemberInfo,
        createTime,
        newSignature
    )

    override val sponsorKeyId: SecureHash by lazy { initialMemberKey.id }

    override fun verify(groupInfo: GroupInfo) {
        require(groupInfo == GroupInfo.EmptyGroup) {
            "Create cannot be applied to an existing group"
        }
        val signatureObject = this.changeSignature(
            DigitalSignature("CREATEGROUPREQUEST", ByteArray(0))
        ).serialize()
        founderSignature.verify(initialMemberKey, signatureObject)
    }

    override fun toString(): String =
        "GroupCreate[groupId=$groupId, groupIdentifier=$groupIdentifier, initialMemberName=$initialMemberName, initialMemberId=${initialMemberKey.id}, groupInfo=$groupInfo]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupCreate

        if (groupId != other.groupId) return false
        if (groupIdentifier != other.groupIdentifier) return false
        if (groupInfo != other.groupInfo) return false
        if (initialMemberName != other.initialMemberName) return false
        if (initialMemberKey != other.initialMemberKey) return false
        if (initialMemberDhKey != other.initialMemberDhKey) return false
        if (initialMemberAddress != other.initialMemberAddress) return false
        if (initialMemberInfo != other.initialMemberInfo) return false
        if (createTime != other.createTime) return false
        if (founderSignature != other.founderSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = groupId.hashCode()
        result = 31 * result + groupIdentifier.hashCode()
        result = 31 * result + groupInfo.hashCode()
        result = 31 * result + initialMemberName.hashCode()
        result = 31 * result + initialMemberKey.hashCode()
        result = 31 * result + initialMemberDhKey.hashCode()
        result = 31 * result + initialMemberAddress.hashCode()
        result = 31 * result + initialMemberInfo.hashCode()
        result = 31 * result + createTime.hashCode()
        result = 31 * result + founderSignature.hashCode()
        return result
    }
}