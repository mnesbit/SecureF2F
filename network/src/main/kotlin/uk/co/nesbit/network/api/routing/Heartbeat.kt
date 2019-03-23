package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.SecureVersion
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.routing.VersionedRoute.Companion.NONCE_SIZE
import uk.co.nesbit.network.api.services.KeyService
import java.nio.ByteBuffer
import java.util.*

class Heartbeat private constructor(private val schemaId: SecureHash,
                                    val currentVersion: SecureVersion,
                                    val versionedRouteSignature: DigitalSignature,
                                    val nextExpectedNonce: ByteArray) : AvroConvertible {
    constructor(heartbeat: GenericRecord) :
            this(SecureHash("SHA-256", heartbeat.getTyped("schemaFingerprint")),
                    heartbeat.getTyped("currentVersion", ::SecureVersion),
                    heartbeat.getTyped("versionedRouteSignature", ::DigitalSignature),
                    heartbeat.getTyped("nextExpectedNonce"))

    constructor (currentVersion: SecureVersion,
                 versionedRouteSignature: DigitalSignature,
                 nextExpectedNonce: ByteArray) : this(SecureHash("SHA-256", schemaFingerprint),
            currentVersion,
            versionedRouteSignature,
            nextExpectedNonce)

    init {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(nextExpectedNonce.size == NONCE_SIZE)
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val heartbeatSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureVersion.secureVersionSchema.fullName to SecureVersion.secureVersionSchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/heartbeat.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", heartbeatSchema)

        fun deserialize(bytes: ByteArray): Heartbeat {
            val heartbeatRecord = heartbeatSchema.deserialize(bytes)
            return Heartbeat(heartbeatRecord)
        }

        fun tryDeserialize(bytes: ByteArray): Heartbeat? {
            if (bytes.size <= schemaFingerprint.size + NONCE_SIZE) {
                return null
            }
            if (ByteBuffer.wrap(bytes, 0, schemaFingerprint.size) != ByteBuffer.wrap(schemaFingerprint)) {
                return null
            }
            return try {
                val heartbeat = Heartbeat.deserialize(bytes)
                val reserialized = heartbeat.serialize()
                if (Arrays.equals(bytes, reserialized)) {
                    heartbeat
                } else {
                    null
                }
            } catch (ex: Exception) {
                null
            }
        }

        fun createHeartbeat(expectedNonce: ByteArray, from: VersionedIdentity, toKeyService: KeyService, toId: SecureHash): Heartbeat {
            val newNonce = ByteArray(NONCE_SIZE)
            toKeyService.random.nextBytes(newNonce)
            val to = toKeyService.getVersion(toId)
            val versionedRoute = VersionedRoute(expectedNonce, from, to)
            val serializedRoute = versionedRoute.serialize()
            val signature = toKeyService.sign(to.id, serializedRoute)
            return Heartbeat(to.currentVersion, signature.toDigitalSignature(), newNonce)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val heartbeatRecord = GenericData.Record(heartbeatSchema)
        heartbeatRecord.putTyped("schemaFingerprint", schemaFingerprint)
        heartbeatRecord.putTyped("currentVersion", currentVersion)
        heartbeatRecord.putTyped("versionedRouteSignature", versionedRouteSignature)
        heartbeatRecord.putTyped("nextExpectedNonce", nextExpectedNonce)
        return heartbeatRecord
    }

    fun verify(expectedNonce: ByteArray, from: VersionedIdentity, to: VersionedIdentity): VersionedIdentity {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(nextExpectedNonce.size == NONCE_SIZE)
        require(to.identity.verifyChainValue(currentVersion)) { "Mismatched version" }
        require(to.currentVersion.version <= currentVersion.version) { "Mismatched version" }
        val latestToVersion = VersionedIdentity(to.identity, currentVersion)
        val versionedRoute = VersionedRoute(expectedNonce, from, latestToVersion)
        val serializedRoute = versionedRoute.serialize()
        versionedRouteSignature.verify(to.identity.signingPublicKey, serializedRoute)
        return latestToVersion
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Heartbeat

        if (schemaId != other.schemaId) return false
        if (currentVersion != other.currentVersion) return false
        if (versionedRouteSignature != other.versionedRouteSignature) return false
        if (!Arrays.equals(nextExpectedNonce, other.nextExpectedNonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + currentVersion.hashCode()
        result = 31 * result + versionedRouteSignature.hashCode()
        result = 31 * result + Arrays.hashCode(nextExpectedNonce)
        return result
    }
}

