package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import java.util.*

class VersionedRoute private constructor(private val schemaId: SecureHash,
                                         val nonce: ByteArray,
                                         val from: VersionedIdentity,
                                         val to: VersionedIdentity) : AvroConvertible {
    constructor(versionedRoute: GenericRecord) :
            this(
                SecureHash("SHA-256", versionedRoute.getTyped("schemaFingerprint")),
                versionedRoute.getTyped("nonce"),
                versionedRoute.getTyped("from"),
                versionedRoute.getTyped("to")
            )

    constructor(nonce: ByteArray,
                from: VersionedIdentity,
                to: VersionedIdentity) : this(SecureHash("SHA-256", schemaFingerprint), nonce, from, to)

    init {
        require(schemaId == SecureHash("SHA-256", schemaFingerprint))
        require(nonce.size == NONCE_SIZE)
    }

    companion object {
        const val NONCE_SIZE = 16

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val versionedRouteSchema: Schema = Schema.Parser()
            .addTypes(mapOf(VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/versionedroute.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", versionedRouteSchema)

        fun deserialize(bytes: ByteArray): VersionedRoute {
            val versionedRouteRecord = versionedRouteSchema.deserialize(bytes)
            return VersionedRoute(versionedRouteRecord)
        }
    }

    val entry: RouteEntry get() = RouteEntry(nonce, to)

    override fun toGenericRecord(): GenericRecord {
        val versionedRouteRecord = GenericData.Record(versionedRouteSchema)
        versionedRouteRecord.putTyped("schemaFingerprint", schemaFingerprint)
        versionedRouteRecord.putTyped("nonce", nonce)
        versionedRouteRecord.putTyped("from", from)
        versionedRouteRecord.putTyped("to", to)
        return versionedRouteRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as VersionedRoute

        if (schemaId != other.schemaId) return false
        if (!Arrays.equals(nonce, other.nonce)) return false
        if (from != other.from) return false
        if (to != other.to) return false

        return true
    }

    override fun hashCode(): Int {
        var result = schemaId.hashCode()
        result = 31 * result + Arrays.hashCode(nonce)
        result = 31 * result + from.hashCode()
        result = 31 * result + to.hashCode()
        return result
    }
}

