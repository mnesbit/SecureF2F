package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.routing.VersionedRoute.Companion.NONCE_SIZE
import uk.co.nesbit.network.api.services.KeyService
import java.nio.ByteBuffer
import java.util.*

class Ping private constructor(
    private val schemaId: SecureHash,
    val nonce: ByteArray
) : AvroConvertible {
    constructor(ping: GenericRecord) :
            this(
                SecureHash("SHA-256", ping.getTyped("schemaFingerprint")),
                ping.getTyped("nonce")
            )

    init {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(nonce.size == NONCE_SIZE)
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val pingSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/ping.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", pingSchema)

        fun deserialize(bytes: ByteArray): Ping {
            val pingRecord = pingSchema.deserialize(bytes)
            return Ping(pingRecord)
        }

        fun tryDeserialize(bytes: ByteArray): Ping? {
            if (bytes.size < schemaFingerprint.size + NONCE_SIZE) {
                return null
            }
            if (ByteBuffer.wrap(bytes, 0, schemaFingerprint.size) != ByteBuffer.wrap(schemaFingerprint)) {
                return null
            }
            return try {
                val ping = deserialize(bytes)
                val reserialized = ping.serialize()
                if (Arrays.equals(bytes, reserialized)) {
                    ping
                } else {
                    null
                }
            } catch (ex: Exception) {
                null
            }
        }

        fun createPing(keyService: KeyService): Ping {
            val nonce = ByteArray(NONCE_SIZE)
            keyService.random.nextBytes(nonce)
            return Ping(SecureHash("SHA-256", schemaFingerprint), nonce)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val pingRecord = GenericData.Record(pingSchema)
        pingRecord.putTyped("schemaFingerprint", schemaFingerprint)
        pingRecord.putTyped("nonce", nonce)
        return pingRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Ping

        if (schemaId != other.schemaId) return false
        if (!nonce.contentEquals(other.nonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + nonce.contentHashCode()
        return result
    }

}