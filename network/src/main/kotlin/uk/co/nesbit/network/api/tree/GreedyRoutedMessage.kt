package uk.co.nesbit.network.api.tree

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.Hello.Companion.NONCE_SIZE
import java.security.SignatureException
import java.time.Instant
import java.time.temporal.ChronoUnit

class GreedyRoutedMessage private constructor(
        val destination: NetworkAddressInfo,
        val ttl: Int,
        val payload: ByteArray,
        val pathInfo: List<EncryptedSecurePathItem>,
        val lastLinkSignature: DigitalSignature
) : Message {
    constructor(greedyRoutedRecord: GenericRecord) :
            this(
                    greedyRoutedRecord.getTyped("destination"),
                    greedyRoutedRecord.getTyped("ttl"),
                    greedyRoutedRecord.getTyped("payload"),
                    greedyRoutedRecord.getObjectArray("pathInfo", ::EncryptedSecurePathItem),
                    greedyRoutedRecord.getTyped("lastLinkSignature")
            )

    companion object {
        const val BaseTimeError = 10000L
        const val TimeErrorPerHop = 60000L

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val greedyRoutedSchema: Schema = Schema.Parser()
                .addTypes(
                        mapOf(
                                NetworkAddressInfo.networkAddressInfoSchema.fullName to NetworkAddressInfo.networkAddressInfoSchema,
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
                finalDestination: NetworkAddressInfo,
                ttl: Int,
                payload: ByteArray,
                path: List<EncryptedSecurePathItem>,
                linkId: ByteArray
        ): ByteArray {
            require(linkId.size == NONCE_SIZE) {
                "LinkId must be 16 bytes long"
            }
            val dummyObject = GreedyRoutedMessage(
                    finalDestination,
                    ttl,
                    payload,
                    path,
                    DigitalSignature("DUMMY", ByteArray(0))
            )
            val pathHash = SecureHash.secureHash(dummyObject.serialize())
            return concatByteArrays(linkId, pathHash.bytes)
        }

        fun createGreedRoutedMessage(
                destination: NetworkAddressInfo,
                ttl: Int,
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
                    destination,
                    ttl,
                    payload,
                    path,
                    linkId
            )
            val linkSignature = keyService.sign(from.id, linkSignOver).toDigitalSignature()
            return GreedyRoutedMessage(
                    destination,
                    ttl,
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
                    message.destination.identity.identity,
                    keyService,
                    now
            )
            val linkSignOver = createLinkSignatureBytes(
                    message.destination,
                    message.ttl,
                    message.payload,
                    path,
                    linkId
            )
            val linkSignature = keyService.sign(from.id, linkSignOver).toDigitalSignature()
            return GreedyRoutedMessage(
                    message.destination,
                    message.ttl,
                    message.payload,
                    path,
                    linkSignature
            )
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val greedyRoutedRecord = GenericData.Record(greedyRoutedSchema)
        greedyRoutedRecord.putTyped("destination", destination)
        greedyRoutedRecord.putTyped("ttl", ttl)
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
        destination.verify()
        require(pathInfo.size <= ttl) {
            "reverse path info longer than allowed ttl"
        }
        val selfIdentity = keyService.getVersion(self)
        val linkSignOver = createLinkSignatureBytes(
                destination,
                ttl,
                payload,
                pathInfo,
                linkId
        )
        try {
            lastLinkSignature.verify(prevNode.identity.signingPublicKey, linkSignOver)
        } catch (ex: SignatureException) {
            throw SignatureException("Bad link signature")
        }
        if (destination.identity.id == self) {
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
                require(
                    next.currentVersion.minVersion >= keyService.minVersion
                            && next.currentVersion.maxVersion <= keyService.maxVersion
                ) {
                    "Version ranges less strict than locally required"
                }
                require(timeDiff >= -BaseTimeError) {
                    "Time too far in future $timeDiff ms"
                }
                require(timeDiff <= BaseTimeError + (securePathList.size - index) * TimeErrorPerHop) {
                    "Time difference too great $timeDiff ms"
                }
                val prevTimestampBytes = timestamp.toEpochMilli().toByteArray()
                val pathSignOverNext = concatByteArrays(prevTimestampBytes, next.id.serialize())
                try {
                    curr.signatureOverNext.verify(curr.identity.identity.signingPublicKey, pathSignOverNext)
                } catch (ex: SignatureException) {
                    throw SignatureException("Bad path signature")
                }
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
        if (ttl != other.ttl) return false
        if (!payload.contentEquals(other.payload)) return false
        if (pathInfo != other.pathInfo) return false
        if (lastLinkSignature != other.lastLinkSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = destination.hashCode()
        result = 31 * result + ttl
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + pathInfo.hashCode()
        result = 31 * result + lastLinkSignature.hashCode()
        return result
    }


}