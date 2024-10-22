package uk.co.nesbit.crypto.blockdag

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.setsync.InvertibleBloomFilter
import java.security.SignatureException
import java.util.*

class BlockSyncMessage private constructor(
    val sender: SecureHash,
    val invertibleBloomFilter: InvertibleBloomFilter,
    val heads: SortedSet<Block>,
    val directRequests: SortedSet<SecureHash>,
    val blocks: SortedSet<Block>,
    val signature: DigitalSignature
) : AvroConvertible {

    constructor(syncMessageRecord: GenericRecord) : this(
        syncMessageRecord.getTyped("sender"),
        syncMessageRecord.getTyped("invertibleBloomFilter", ::InvertibleBloomFilter),
        syncMessageRecord.getObjectArray("heads", ::Block).toSortedSet(),
        syncMessageRecord.getObjectArray("directRequests", ::SecureHash).toSortedSet(),
        syncMessageRecord.getObjectArray("blocks", ::Block).toSortedSet(),
        syncMessageRecord.getTyped("signature", ::DigitalSignature)
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val syncMessageSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    InvertibleBloomFilter.ibfSchema.fullName to InvertibleBloomFilter.ibfSchema,
                    Block.blockSchema.fullName to Block.blockSchema,
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/blockdag/blocksyncmessage.avsc"))

        fun deserialize(bytes: ByteArray): BlockSyncMessage {
            val syncMessageRecord = syncMessageSchema.deserialize(bytes)
            return BlockSyncMessage(syncMessageRecord)
        }

        fun createBlockSyncMessage(
            sender: SecureHash,
            invertibleBloomFilter: InvertibleBloomFilter,
            heads: Iterable<Block>,
            directRequests: Iterable<SecureHash>,
            blocks: Iterable<Block>,
            signingService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): BlockSyncMessage {
            val templateObject = BlockSyncMessage(
                sender,
                invertibleBloomFilter,
                heads.toSortedSet(),
                directRequests.toSortedSet(),
                blocks.toSortedSet(),
                DigitalSignature("SYNCMESSAGE", ByteArray(0))
            )
            val signatureBytes = templateObject.serialize()
            val signature = signingService(sender, signatureBytes)
            return templateObject.changeSignature(signature.toDigitalSignature())
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val syncMessageRecord = GenericData.Record(syncMessageSchema)
        syncMessageRecord.putTyped("sender", sender)
        syncMessageRecord.putTyped("invertibleBloomFilter", invertibleBloomFilter)
        syncMessageRecord.putObjectArray("heads", heads.toList())
        syncMessageRecord.putObjectArray("directRequests", directRequests.toList())
        syncMessageRecord.putObjectArray("blocks", blocks.toList())
        syncMessageRecord.putTyped("signature", signature)
        return syncMessageRecord
    }

    private fun changeSignature(newSignature: DigitalSignature): BlockSyncMessage = BlockSyncMessage(
        sender,
        invertibleBloomFilter,
        heads,
        directRequests,
        blocks,
        newSignature
    )

    fun verify(memberService: MemberService) {
        val senderKey = memberService.getMemberKey(sender) ?: throw SignatureException("Unknown sender $sender")
        val verifyObject = changeSignature(DigitalSignature("SYNCMESSAGE", ByteArray(0)))
        val verifyBytes = verifyObject.serialize()
        signature.verify(senderKey, verifyBytes)
        for (block in blocks) {
            block.verify(memberService)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as BlockSyncMessage

        if (sender != other.sender) return false
        if (invertibleBloomFilter != other.invertibleBloomFilter) return false
        if (heads != other.heads) return false
        if (directRequests != other.directRequests) return false
        if (blocks != other.blocks) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sender.hashCode()
        result = 31 * result + invertibleBloomFilter.hashCode()
        result = 31 * result + heads.hashCode()
        result = 31 * result + directRequests.hashCode()
        result = 31 * result + blocks.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }


}