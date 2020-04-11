package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import java.nio.ByteBuffer
import java.util.*

enum class TreeStatus {
    Isolated,
    Correct,
    ErrorBroadcast,
    ErrorFeedback
}

class TreeState private constructor(
    private val schemaId: SecureHash,
    val currentSeqNo: Long,
    val replySeqNo: Long?,
    val status: TreeStatus,
    val pathToRoot: List<SphinxPublicIdentity>
) : AvroConvertible, Comparable<TreeState> {
    constructor(
        currentSeqNo: Long,
        replySeqNo: Long?,
        status: TreeStatus,
        pathToRoot: List<SphinxPublicIdentity>
    ) :
            this(
                SecureHash("SHA-256", schemaFingerprint),
                currentSeqNo,
                replySeqNo,
                status,
                pathToRoot
            )

    constructor(treeState: GenericRecord) :
            this(
                SecureHash("SHA-256", treeState.getTyped("schemaFingerprint")),
                treeState.getTyped("currentSeqNo"),
                treeState.getTyped("replySeqNo"),
                treeState.getTyped("status"),
                treeState.getObjectArray("pathToRoot", ::SphinxPublicIdentity)
            )

    init {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val treeStateSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/treestate.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", treeStateSchema)

        fun deserialize(bytes: ByteArray): TreeState {
            val treeStateRecord = treeStateSchema.deserialize(bytes)
            return TreeState(treeStateRecord)
        }

        fun tryDeserialize(bytes: ByteArray): TreeState? {
            if (bytes.size < schemaFingerprint.size) {
                return null
            }
            if (ByteBuffer.wrap(bytes, 0, schemaFingerprint.size) != ByteBuffer.wrap(schemaFingerprint)) {
                return null
            }
            return try {
                val treeState = deserialize(bytes)
                val reserialized = treeState.serialize()
                if (Arrays.equals(bytes, reserialized)) {
                    treeState
                } else {
                    null
                }
            } catch (ex: Exception) {
                null
            }
        }

        fun comparePath(left: List<SphinxPublicIdentity>, right: List<SphinxPublicIdentity>): Int {
            require(left.isNotEmpty() && right.isNotEmpty()) { "Paths must contain at least one item" }
            val leftRoot = left.first()
            val rightRoot = right.first()
            if (leftRoot != rightRoot) {
                return leftRoot.id.compareTo(rightRoot.id)
            }
            val depthDiff = right.size - left.size
            if (depthDiff != 0) {
                return depthDiff
            }
            for (index in left.indices) {
                val leftItem = left[index]
                val rightItem = right[index]
                val comp = leftItem.id.compareTo(rightItem.id)
                if (comp != 0) {
                    return comp
                }
            }
            return 0
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val treeStateRecord = GenericData.Record(treeStateSchema)
        treeStateRecord.putTyped("schemaFingerprint", schemaFingerprint)
        treeStateRecord.putTyped("currentSeqNo", currentSeqNo)
        treeStateRecord.putTyped("replySeqNo", replySeqNo)
        treeStateRecord.putTyped("status", status)
        treeStateRecord.putObjectArray("pathToRoot", pathToRoot)
        return treeStateRecord
    }

    fun copy(
        currentSeqNo: Long = this.currentSeqNo,
        replySeqNo: Long? = this.replySeqNo,
        status: TreeStatus = this.status,
        pathToRoot: List<SphinxPublicIdentity> = this.pathToRoot
    ): TreeState = TreeState(currentSeqNo, replySeqNo, status, pathToRoot)

    val depth: Int get() = pathToRoot.size
    val parent: SecureHash?
        get() {
            if (pathToRoot.size < 2) {
                return null
            }
            return pathToRoot[pathToRoot.size - 2].id
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TreeState

        if (schemaId != other.schemaId) return false
        if (currentSeqNo != other.currentSeqNo) return false
        if (replySeqNo != other.replySeqNo) return false
        if (status != other.status) return false
        if (pathToRoot != other.pathToRoot) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + currentSeqNo.hashCode()
        result = 31 * result + (replySeqNo?.hashCode() ?: 0)
        result = 31 * result + status.hashCode()
        result = 31 * result + pathToRoot.hashCode()
        return result
    }

    override fun compareTo(other: TreeState): Int = comparePath(pathToRoot, other.pathToRoot)
}