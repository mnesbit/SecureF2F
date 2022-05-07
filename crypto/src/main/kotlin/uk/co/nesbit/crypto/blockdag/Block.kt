package uk.co.nesbit.crypto.blockdag

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.merkle.MerkleTree
import java.security.SignatureException
import java.util.*

class Block private constructor(
    val origin: SecureHash,
    val predecessors: SortedSet<SecureHash>,
    val payload: ByteArray,
    val signature: DigitalSignature
) : AvroConvertible, Comparable<Block> {
    constructor(blockRecord: GenericRecord) : this(
        blockRecord.getTyped("origin"),
        blockRecord.getObjectArray("predecessors", ::SecureHash).toSortedSet(),
        blockRecord.getTyped("payload"),
        blockRecord.getTyped("signature"),
    )

    init {
        require(predecessors.isNotEmpty()) { "predecessors list must not be empty" }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val blockSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/blockdag/block.avsc"))

        fun createBlock(
            origin: SecureHash,
            predecessors: List<SecureHash>,
            payload: ByteArray,
            signingService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): Block {
            require(predecessors.isNotEmpty()) { "predecessors list must not be empty" }
            val templateObject = Block(
                origin,
                predecessors.toSortedSet(),
                payload,
                DigitalSignature("DUMMY", ByteArray(0))
            )
            val signatureBytes = templateObject.id.serialize()
            val signature = signingService(origin, signatureBytes)
            return templateObject.changeSignature(signature.toDigitalSignature())
        }

        fun createRootBlock(
            origin: SecureHash,
            signingService: (SecureHash, ByteArray) -> DigitalSignatureAndKey
        ): Block = createBlock(origin, listOf(origin), ByteArray(0), signingService)

        fun deserialize(bytes: ByteArray): Block {
            val blockRecord = blockSchema.deserialize(bytes)
            return Block(blockRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val blockRecord = GenericData.Record(blockSchema)
        blockRecord.putTyped("origin", origin)
        blockRecord.putObjectArray("predecessors", predecessors.toList())
        blockRecord.putTyped("payload", payload)
        blockRecord.putTyped("signature", signature)
        return blockRecord
    }

    val id: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val merkleLeaves = listOf(origin.serialize()) +
                predecessors.sorted().map { it.serialize() } +
                payload
        val merkleTree = MerkleTree.createMerkleTree(merkleLeaves)
        merkleTree.root
    }

    val isRoot: Boolean get() = predecessors.size == 1 && predecessors.first() == origin && payload.isEmpty()

    private fun changeSignature(newSignature: DigitalSignature): Block = Block(
        origin,
        predecessors,
        payload,
        newSignature
    )

    fun verify(memberService: MemberService) {
        val originKey = memberService.getMemberKey(origin) ?: throw SignatureException("Unknown origin $origin")
        val signatureBytes = id.serialize()
        signature.verify(originKey, signatureBytes)
        if (predecessors.size == 1 && predecessors.first() == origin) {
            if (payload.isNotEmpty()) {
                throw SignatureException("root blocks must have empty payload")
            }
        }
    }

    override fun compareTo(other: Block): Int {
        return id.compareTo(other.id)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Block

        if (origin != other.origin) return false
        if (predecessors != other.predecessors) return false
        if (!payload.contentEquals(other.payload)) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = origin.hashCode()
        result = 31 * result + predecessors.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.hashCode()
        return result
    }
}