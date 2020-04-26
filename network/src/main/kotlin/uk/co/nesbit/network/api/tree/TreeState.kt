package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.services.KeyService
import java.time.Instant
import java.time.temporal.ChronoUnit

class TreeState(
    val path: SecurePath,
    val linkSignature: DigitalSignature
) : Message {
    constructor(treeStateRecord: GenericRecord) :
            this(
                treeStateRecord.getTyped("path"),
                treeStateRecord.getTyped("linkSignature")
            )

    companion object {
        const val BaseTimeError = 10000L
        const val TimeErrorPerHop = 200000L

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val treeStateSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecurePath.securePathSchema.fullName to SecurePath.securePathSchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/treestate.avsc"))

        fun deserialize(bytes: ByteArray): TreeState {
            val treeStateRecord = treeStateSchema.deserialize(bytes)
            return TreeState(treeStateRecord)
        }

        fun createTreeState(
            appendTo: TreeState?,
            linkId: ByteArray,
            from: VersionedIdentity,
            to: VersionedIdentity,
            keyService: KeyService,
            now: Instant
        ): TreeState {
            val pathList = SecurePath.createSecurePathList(appendTo?.path?.path, from, to, keyService, now)
            val path = SecurePath(pathList)
            val pathHash = SecureHash.secureHash(path.serialize())
            val linkSignOver = concatByteArrays(linkId, pathHash.bytes)
            val linkSignature = keyService.sign(from.id, linkSignOver).toDigitalSignature()
            return TreeState(path, linkSignature)
        }
    }

    val shortPath: List<SphinxPublicIdentity> by lazy {
        path.shortPath
    }

    val root: SecureHash by lazy {
        path.path.first().identity.id
    }

    val depth: Int by lazy {
        path.path.size
    }

    override fun toGenericRecord(): GenericRecord {
        val routeTableRecord = GenericData.Record(treeStateSchema)
        routeTableRecord.putTyped("path", path)
        routeTableRecord.putTyped("linkSignature", linkSignature)
        return routeTableRecord
    }

    fun stale(now: Instant): Boolean {
        for (index in path.path.indices) {
            val curr = path.path[index]
            val timestamp = curr.timestamp
            val timeDiff = ChronoUnit.MILLIS.between(timestamp, now)
            if (timeDiff < -BaseTimeError) {
                return true
            }
            if (timeDiff > BaseTimeError + (1 + index) * TimeErrorPerHop) {
                return true
            }
        }
        return false
    }

    fun verify(
        secureLinkId: ByteArray,
        self: VersionedIdentity,
        now: Instant
    ) {
        val uniqueIds = path.path.map { it.identity.id }.toSet()
        require(uniqueIds.size == path.path.size) {
            "No circular paths allowed"
        }
        val minHash = uniqueIds.min()
        require(path.path.first().identity.id == minHash) {
            "root should always be lowest hash in chain"
        }
        val nowRounded = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
        val pathHash = SecureHash.secureHash(path.serialize())
        val linkSignOver = concatByteArrays(secureLinkId, pathHash.bytes)
        val from = path.path.last().identity
        linkSignature.verify(from.identity.signingPublicKey, linkSignOver)
        for (index in path.path.indices) {
            val curr = path.path[index]
            val timestamp = curr.timestamp
            val timeDiff = ChronoUnit.MILLIS.between(timestamp, nowRounded)
            val next = if (index < path.path.size - 1) {
                path.path[index + 1].identity
            } else {
                self
            }
            require(timeDiff >= -BaseTimeError) {
                "Time too far in future $timeDiff ms"
            }
            require(timeDiff <= BaseTimeError + (1 + index) * TimeErrorPerHop) {
                "Time difference too great $timeDiff ms"
            }
            val prevTimestampBytes = timestamp.toEpochMilli().toByteArray()
            val pathSignOverNext = concatByteArrays(prevTimestampBytes, next.id.serialize())
            curr.signatureOverNext.verify(curr.identity.identity.signingPublicKey, pathSignOverNext)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TreeState

        if (path != other.path) return false
        if (linkSignature != other.linkSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = path.hashCode()
        result = 31 * result + linkSignature.hashCode()
        return result
    }
}