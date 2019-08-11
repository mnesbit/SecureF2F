package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.services.KeyService
import java.nio.ByteBuffer
import java.util.*

class Pong private constructor(
    private val schemaId: SecureHash,
    val identity: VersionedIdentity,
    val signature: DigitalSignature
) : AvroConvertible {
    constructor(pong: GenericRecord) :
            this(
                SecureHash("SHA-256", pong.getTyped("schemaFingerprint")),
                pong.getTyped("identity", ::VersionedIdentity),
                pong.getTyped("signature", ::DigitalSignature)
            )

    init {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val pongSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/pong.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", pongSchema)

        fun deserialize(bytes: ByteArray): Pong {
            val pongRecord = pongSchema.deserialize(bytes)
            return Pong(pongRecord)
        }

        fun tryDeserialize(bytes: ByteArray): Pong? {
            if (bytes.size <= schemaFingerprint.size) {
                return null
            }
            if (ByteBuffer.wrap(bytes, 0, schemaFingerprint.size) != ByteBuffer.wrap(schemaFingerprint)) {
                return null
            }
            return try {
                val pong = deserialize(bytes)
                val reserialized = pong.serialize()
                if (Arrays.equals(bytes, reserialized)) {
                    pong
                } else {
                    null
                }
            } catch (ex: Exception) {
                null
            }
        }

        fun createPong(ping: Ping, id: SecureHash, keyService: KeyService): Pong {
            val signingBytes = concatByteArrays("pong".toByteArray(), schemaFingerprint, ping.nonce, id.serialize())
            val signature = keyService.sign(id, signingBytes)
            return Pong(
                SecureHash("SHA-256", schemaFingerprint),
                keyService.getVersion(id),
                signature.toDigitalSignature()
            )
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val pongRecord = GenericData.Record(pongSchema)
        pongRecord.putTyped("schemaFingerprint", schemaFingerprint)
        pongRecord.putTyped("identity", identity)
        pongRecord.putTyped("signature", signature)
        return pongRecord
    }

    fun verify(originalPing: Ping): VersionedIdentity {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        val signingBytes =
            concatByteArrays("pong".toByteArray(), schemaFingerprint, originalPing.nonce, identity.id.serialize())
        signature.verify(identity.identity.signingPublicKey, signingBytes)
        return identity
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Pong

        if (schemaId != other.schemaId) return false
        if (identity != other.identity) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + identity.hashCode()
        result = 31 * result + signature.hashCode()
        return result
    }

}