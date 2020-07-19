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
        val path1: SecurePath,
        val path2: SecurePath,
        val path3: SecurePath,
        val linkSignature: DigitalSignature
) : Message {
    constructor(treeStateRecord: GenericRecord) :
            this(
                    treeStateRecord.getTyped("path1"),
                    treeStateRecord.getTyped("path2"),
                    treeStateRecord.getTyped("path3"),
                    treeStateRecord.getTyped("linkSignature")
            )

    companion object {
        const val BaseTimeError = 10000L
        const val TimeErrorPerHop = 45000L

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
                appendTo1: SecurePath?,
                appendTo2: SecurePath?,
                appendTo3: SecurePath?,
                linkId: ByteArray,
                from: VersionedIdentity,
                to: VersionedIdentity,
                keyService: KeyService,
                now: Instant
        ): TreeState {
            val (path1, path1Hash) = appendPath(appendTo1, from, to, keyService, now)
            val (path2, path2Hash) = appendPath(appendTo2, from, to, keyService, now)
            val (path3, path3Hash) = appendPath(appendTo3, from, to, keyService, now)
            val linkSignOver = concatByteArrays(linkId, path1Hash.bytes, path2Hash.bytes, path3Hash.bytes)
            val linkSignature = keyService.sign(from.id, linkSignOver).toDigitalSignature()
            return TreeState(path1, path2, path3, linkSignature)
        }

        private fun appendPath(
                parentPath: SecurePath?,
                from: VersionedIdentity,
                to: VersionedIdentity,
                keyService: KeyService,
                now: Instant
        ): Pair<SecurePath, SecureHash> {
            val pathList = SecurePath.createSecurePathList(parentPath?.path, from, to, keyService, now)
            val path = SecurePath(pathList)
            val pathHash = SecureHash.secureHash(path.serialize())
            return Pair(path, pathHash)
        }
    }

    val paths: List<SecurePath> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(path1, path2, path3)
    }

    val shortPaths: List<List<SphinxPublicIdentity>> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(path1.shortPath, path2.shortPath, path3.shortPath)
    }

    val treeAddress: NetworkAddressInfo by lazy(LazyThreadSafetyMode.PUBLICATION) {
        NetworkAddressInfo(path1.path.last().identity,
                path1.path.map { it.identity.id },
                path2.path.map { it.identity.id },
                path3.path.map { it.identity.id })
    }

    val roots: List<SecureHash> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(path1.path.first().identity.id, path2.path.first().identity.id, path3.path.first().identity.id)
    }

    val depths: List<Int> by lazy(LazyThreadSafetyMode.PUBLICATION) {
        listOf(path1.path.size, path2.path.size, path3.path.size)
    }

    override fun toGenericRecord(): GenericRecord {
        val routeTableRecord = GenericData.Record(treeStateSchema)
        routeTableRecord.putTyped("path1", path1)
        routeTableRecord.putTyped("path2", path2)
        routeTableRecord.putTyped("path3", path3)
        routeTableRecord.putTyped("linkSignature", linkSignature)
        return routeTableRecord
    }

    fun stale(now: Instant): Boolean {
        for (path in listOf(path1, path2, path3)) {
            for (index in path.path.indices) {
                val curr = path.path[index]
                val timestamp = curr.timestamp
                val timeDiff = ChronoUnit.MILLIS.between(timestamp, now)
                if (timeDiff < -BaseTimeError) {
                    return true
                }
                if (timeDiff > BaseTimeError + (path.path.size - index) * TimeErrorPerHop) {
                    return true
                }
            }
        }
        return false
    }

    private fun verifyPath(
            path: SecurePath,
            index: Int,
            self: VersionedIdentity,
            now: Instant
    ): SecureHash {
        val uniqueIds = path.path.map { it.identity.id }.toSet()
        require(uniqueIds.size == path.path.size) {
            "No circular paths allowed"
        }
        val minHash = uniqueIds.minBy { SecureHash.secureHash(concatByteArrays(index.toByteArray(), it.bytes)) }
        require(path.path.first().identity.id == minHash) {
            "root should always be lowest hash in chain"
        }
        val nowRounded = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
        val pathHash = SecureHash.secureHash(path.serialize())
        for (hop in path.path.indices) {
            val curr = path.path[hop]
            val timestamp = curr.timestamp
            val timeDiff = ChronoUnit.MILLIS.between(timestamp, nowRounded)
            val next = if (hop < path.path.size - 1) {
                path.path[hop + 1].identity
            } else {
                self
            }
            require(timeDiff >= -BaseTimeError) {
                "Time too far in future $timeDiff ms"
            }
            require(timeDiff <= BaseTimeError + (path.path.size - hop) * TimeErrorPerHop) {
                "Time difference too great $timeDiff ms"
            }
            val prevTimestampBytes = timestamp.toEpochMilli().toByteArray()
            val pathSignOverNext = concatByteArrays(prevTimestampBytes, next.id.serialize())
            curr.signatureOverNext.verify(curr.identity.identity.signingPublicKey, pathSignOverNext)
        }
        return pathHash
    }

    fun verify(
            secureLinkId: ByteArray,
            self: VersionedIdentity,
            now: Instant
    ) {
        val from = path1.path.last().identity
        require(from == path2.path.last().identity) {
            "Invalid tree sent from different sources"
        }
        require(from == path3.path.last().identity) {
            "Invalid tree sent from different sources"
        }
        val pathHash1 = verifyPath(path1, 0, self, now)
        val pathHash2 = verifyPath(path2, 1, self, now)
        val pathHash3 = verifyPath(path3, 2, self, now)
        val linkSignOver = concatByteArrays(secureLinkId, pathHash1.bytes, pathHash2.bytes, pathHash3.bytes)
        linkSignature.verify(from.identity.signingPublicKey, linkSignOver)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TreeState

        if (path1 != other.path1) return false
        if (path2 != other.path2) return false
        if (path3 != other.path3) return false
        if (linkSignature != other.linkSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = path1.hashCode()
        result = 31 * result + path2.hashCode()
        result = 31 * result + path3.hashCode()
        result = 31 * result + linkSignature.hashCode()
        return result
    }

}