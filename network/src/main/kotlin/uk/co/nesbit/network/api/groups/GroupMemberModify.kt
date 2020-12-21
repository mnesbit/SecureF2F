package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.services.KeyService

class GroupMemberModify private constructor(
    val newInfo: GroupMemberInfo,
    override val groupStateHash: SecureHash,
    val sponsorKeyId: SecureHash,
    val signatures: List<DigitalSignatureAndKey>
) : GroupChange {
    constructor(groupMemberModifyRecord: GenericRecord) : this(
        groupMemberModifyRecord.getTyped("newInfo"),
        groupMemberModifyRecord.getTyped("groupStateHash"),
        groupMemberModifyRecord.getTyped("sponsorKeyId"),
        groupMemberModifyRecord.getObjectArray("signatures", ::DigitalSignatureAndKey)
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val groupMemberModifySchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignatureAndKey.digitalSignatureAndKeySchema.fullName to DigitalSignatureAndKey.digitalSignatureAndKeySchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    GroupMemberInfo.groupMemberInfoSchema.fullName to GroupMemberInfo.groupMemberInfoSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/groupmembermodify.avsc"))

        fun deserialize(bytes: ByteArray): GroupMemberModify {
            val groupMemberModifyRecord = groupMemberModifySchema.deserialize(bytes)
            return GroupMemberModify(groupMemberModifyRecord)
        }

        private fun checkChanges(
            groupInfo: GroupInfo,
            oldInfo: GroupMemberInfo,
            newInfo: GroupMemberInfo,
            sponsorKeyId: SecureHash
        ) {
            if (sponsorKeyId == newInfo.memberKeyId) {
                if (newInfo.memberKey != oldInfo.memberKey) {
                    val checkChanges = newInfo.copy(
                        memberKey = oldInfo.memberKey,
                        keyIssued = oldInfo.keyIssued,
                        historicKeys = oldInfo.historicKeys
                    )
                    require(checkChanges == oldInfo) {
                        "Self changes only allowed to change keys, not other member details"
                    }
                    require(
                        oldInfo.historicKeys.size + 1 == newInfo.historicKeys.size
                                && oldInfo.historicKeys == newInfo.historicKeys.take(oldInfo.historicKeys.size)
                    ) {
                        "Incorrect historic keys info"
                    }
                    val newHistoricEntry = newInfo.historicKeys.last()
                    require(
                        newHistoricEntry.key == oldInfo.memberKey
                                && newHistoricEntry.validFrom == oldInfo.keyIssued
                                && newHistoricEntry.validUntil == newInfo.keyIssued
                                && newInfo.keyIssued > oldInfo.keyIssued
                    ) {
                        "Incorrect historic keys info"
                    }
                } else if (newInfo.groupDhKey != oldInfo.groupDhKey) {
                    val checkChanges = newInfo.copy(
                        groupDhKey = oldInfo.groupDhKey
                    )
                    require(checkChanges == oldInfo) {
                        "Self changes only allowed to change keys, not other member details"
                    }
                } else if (newInfo.routingAddress != oldInfo.routingAddress) {
                    val checkChanges = newInfo.copy(
                        routingAddress = oldInfo.routingAddress
                    )
                    require(checkChanges == oldInfo) {
                        "Self changes only allowed to change keys, not other member details"
                    }
                }
            } else {
                val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
                require(sponsorInfo != null) {
                    "Sponsor not found"
                }
                require(sponsorInfo.role == GroupMemberRole.ADMIN) {
                    "Sponsor not an admin"
                }
                val checkChanges = newInfo.copy(
                    role = oldInfo.role,
                    otherInfo = oldInfo.otherInfo
                )
                require(checkChanges == oldInfo) {
                    "Admin changes only allowed to role, or otherInfo, not other details"
                }
            }
        }

        fun createModifyRequest(
            groupInfo: GroupInfo,
            newInfo: GroupMemberInfo,
            sponsorKeyId: SecureHash,
            keyService: KeyService
        ): GroupMemberModify {
            val oldInfo = groupInfo.findMemberByName(newInfo.memberName)
            require(oldInfo != null) {
                "Member ${newInfo.memberName} not found"
            }
            val template = GroupMemberModify(
                newInfo,
                groupInfo.groupStateHash,
                sponsorKeyId,
                emptyList()
            )
            val signatureObject = template.serialize()
            checkChanges(groupInfo, oldInfo, newInfo, sponsorKeyId)
            if (sponsorKeyId == newInfo.memberKeyId && newInfo.memberKey != oldInfo.memberKey) {
                return template.changeSignatures(
                    listOf(
                        keyService.sign(sponsorKeyId, signatureObject),
                        keyService.sign(newInfo.historicKeys.last().keyId, signatureObject)
                    )
                )
            }
            return template.changeSignatures(
                listOf(keyService.sign(sponsorKeyId, signatureObject))
            )
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val groupMemberModifyRecord = GenericData.Record(groupMemberModifySchema)
        groupMemberModifyRecord.putTyped("newInfo", newInfo)
        groupMemberModifyRecord.putTyped("groupStateHash", groupStateHash)
        groupMemberModifyRecord.putTyped("sponsorKeyId", sponsorKeyId)
        groupMemberModifyRecord.putObjectArray("signatures", signatures)
        return groupMemberModifyRecord
    }

    override fun verify(groupInfo: GroupInfo) {
        require(groupInfo.groupStateHash == groupStateHash) {
            "Change being applied to mismatched group state"
        }
        val oldInfo = groupInfo.findMemberByName(newInfo.memberName)
        require(oldInfo != null) {
            "Member ${newInfo.memberName} not found"
        }
        checkChanges(groupInfo, oldInfo, newInfo, sponsorKeyId)
        val signatureObject = this.changeSignatures(emptyList()).serialize()
        if (sponsorKeyId == newInfo.memberKeyId && newInfo.memberKey != oldInfo.memberKey) {
            require(signatures.size == 2) {
                "Incorrect number of signatures"
            }
            val oldKeySignature = signatures.single { it.publicKey == oldInfo.memberKey }
            oldKeySignature.verify(signatureObject)
            val newKeySignature = signatures.single { it.publicKey == newInfo.memberKey }
            newKeySignature.verify(signatureObject)
            return
        }
        require(signatures.size == 1) {
            "Incorrect number of signatures"
        }
        val sponsorInfo = groupInfo.findMemberById(sponsorKeyId)
        require(sponsorInfo != null) {
            "Sponsor not found"
        }
        val sponsorSignature = signatures.single { it.publicKey == sponsorInfo.memberKey }
        sponsorSignature.verify(signatureObject)
    }

    private fun changeSignatures(
        newSignatures: List<DigitalSignatureAndKey>
    ): GroupMemberModify = GroupMemberModify(
        newInfo,
        groupStateHash,
        sponsorKeyId,
        newSignatures
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GroupMemberModify

        if (newInfo != other.newInfo) return false
        if (groupStateHash != other.groupStateHash) return false
        if (sponsorKeyId != other.sponsorKeyId) return false
        if (signatures != other.signatures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = newInfo.hashCode()
        result = 31 * result + groupStateHash.hashCode()
        result = 31 * result + sponsorKeyId.hashCode()
        result = 31 * result + signatures.hashCode()
        return result
    }

    override fun toString(): String =
        "GroupMemberModify[newInfo=$newInfo, groupStateHash=$groupStateHash, sponsorKeyId=$sponsorKeyId]"

}