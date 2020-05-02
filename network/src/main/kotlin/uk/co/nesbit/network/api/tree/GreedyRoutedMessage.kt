package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.Hello.Companion.NONCE_SIZE
import java.time.Instant
import java.time.temporal.ChronoUnit

class GreedyRoutedMessage private constructor(
    val destination: SphinxPublicIdentity,
    val treeAddress: List<SecureHash>,
    val payload: ByteArray,
    val pathInfo: List<EncryptedSecurePathItem>,
    val lastLinkSignature: DigitalSignature
) : Message {
    constructor(greedyRoutedRecord: GenericRecord) :
            this(
                greedyRoutedRecord.getTyped("destination"),
                greedyRoutedRecord.getObjectArray("treeAddress", ::SecureHash),
                greedyRoutedRecord.getTyped("payload"),
                greedyRoutedRecord.getObjectArray("pathInfo", ::EncryptedSecurePathItem),
                greedyRoutedRecord.getTyped("lastLinkSignature")
            )

    companion object {
        const val BaseTimeError = 10000L
        const val TimeErrorPerHop = 200000L

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val greedyRoutedSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    EncryptedSecurePathItem.encryptedSecurePathItemSchema.fullName to EncryptedSecurePathItem.encryptedSecurePathItemSchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/tree/greedyroutedmessage.avsc"))

        fun deserialize(bytes: ByteArray): GreedyRoutedMessage {
            val greedyRoutedRecord = greedyRoutedSchema.deserialize(bytes)
            return GreedyRoutedMessage(greedyRoutedRecord)
        }

        private fun createLinkSignatureBytes(
            finalDestination: SphinxPublicIdentity,
            treeAddress: List<SecureHash>,
            payload: ByteArray,
            path: List<EncryptedSecurePathItem>,
            linkId: ByteArray
        ): ByteArray {
            require(linkId.size == NONCE_SIZE) {
                "LinkId must be 16 bytes long"
            }
            val dummyObject = GreedyRoutedMessage(
                finalDestination,
                treeAddress,
                payload,
                path,
                DigitalSignature("DUMMY", ByteArray(0))
            )
            val pathHash = SecureHash.secureHash(dummyObject.serialize())
            val linkSignOver = concatByteArrays(linkId, pathHash.bytes)
            return linkSignOver
        }

        fun createGreedRoutedMessage(
            destination: NetworkAddressInfo,
            payload: ByteArray,
            linkId: ByteArray,
            from: VersionedIdentity,
            nextHop: VersionedIdentity,
            keyService: KeyService,
            now: Instant
        ): GreedyRoutedMessage {
            val finalDestination = destination.identity
            val path = SecurePath.createEncryptedSecurePathList(
                null,
                from,
                nextHop,
                finalDestination.identity,
                keyService,
                now
            )
            val linkSignOver = createLinkSignatureBytes(
                finalDestination.identity,
                destination.treeAddress,
                payload,
                path,
                linkId
            )
            val linkSignature = keyService.sign(from.id, linkSignOver).toDigitalSignature()
            return GreedyRoutedMessage(
                finalDestination.identity,
                destination.treeAddress,
                payload,
                path,
                linkSignature
            )
        }

        fun forwardGreedRoutedMessage(
            message: GreedyRoutedMessage,
            linkId: ByteArray,
            from: VersionedIdentity,
            nextHop: VersionedIdentity,
            keyService: KeyService,
            now: Instant
        ): GreedyRoutedMessage {
            val path = SecurePath.createEncryptedSecurePathList(
                message.pathInfo,
                from,
                nextHop,
                message.destination,
                keyService,
                now
            )
            val linkSignOver = createLinkSignatureBytes(
                message.destination,
                message.treeAddress,
                message.payload,
                path,
                linkId
            )
            val linkSignature = keyService.sign(from.id, linkSignOver).toDigitalSignature()
            return GreedyRoutedMessage(
                message.destination,
                message.treeAddress,
                message.payload,
                path,
                linkSignature
            )
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val greedyRoutedRecord = GenericData.Record(greedyRoutedSchema)
        greedyRoutedRecord.putTyped("destination", destination)
        greedyRoutedRecord.putObjectArray("treeAddress", treeAddress)
        greedyRoutedRecord.putTyped("payload", payload)
        greedyRoutedRecord.putObjectArray("pathInfo", pathInfo)
        greedyRoutedRecord.putTyped("lastLinkSignature", lastLinkSignature)
        return greedyRoutedRecord
    }

    fun verify(
        self: SecureHash,
        linkId: ByteArray,
        prevNode: VersionedIdentity,
        keyService: KeyService,
        now: Instant
    ): List<VersionedIdentity> {
        require(pathInfo.isNotEmpty()) {
            "Path must not be empty"
        }
        require(treeAddress.isNotEmpty()) {
            "Tree address must not be empty"
        }
        require(treeAddress.first() == treeAddress.min()) {
            "invalid root hash"
        }
        require(destination.id == treeAddress.last()) {
            "mismatched destination and treeAddress"
        }
        val selfIdentity = keyService.getVersion(self)
        val linkSignOver = createLinkSignatureBytes(
            destination,
            treeAddress,
            payload,
            pathInfo,
            linkId
        )
        lastLinkSignature.verify(prevNode.identity.signingPublicKey, linkSignOver)
        if (destination.id == self) {
            val nowRounded = now.truncatedTo(ChronoUnit.MILLIS) // round to prevent round trip problems
            val securePathList = pathInfo.map { it.decrypt(self, keyService) }
            for (index in securePathList.indices) {
                val curr = securePathList[index]
                val timestamp = curr.timestamp
                val timeDiff = ChronoUnit.MILLIS.between(timestamp, nowRounded)
                val next = if (index < securePathList.size - 1) {
                    securePathList[index + 1].identity
                } else {
                    selfIdentity
                }
                require(timeDiff >= -BaseTimeError) {
                    "Time too far in future $timeDiff ms"
                }
                require(timeDiff <= BaseTimeError + (1 + index) * TreeState.TimeErrorPerHop) {
                    "Time difference too great $timeDiff ms"
                }
                val prevTimestampBytes = timestamp.toEpochMilli().toByteArray()
                val pathSignOverNext = concatByteArrays(prevTimestampBytes, next.id.serialize())
                curr.signatureOverNext.verify(curr.identity.identity.signingPublicKey, pathSignOverNext)
            }
            return securePathList.map { it.identity }.reversed()
        }
        return emptyList()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as GreedyRoutedMessage

        if (destination != other.destination) return false
        if (treeAddress != other.treeAddress) return false
        if (!payload.contentEquals(other.payload)) return false
        if (pathInfo != other.pathInfo) return false
        if (lastLinkSignature != other.lastLinkSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = destination.hashCode()
        result = 31 * result + treeAddress.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + pathInfo.hashCode()
        result = 31 * result + lastLinkSignature.hashCode()
        return result
    }
}