package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.routing.VersionedRoute.Companion.NONCE_SIZE
import java.util.*

class RouteEntry(val nonce: ByteArray,
                 val to: VersionedIdentity) : AvroConvertible {
    constructor(versionedRoute: GenericRecord) :
            this(versionedRoute.getTyped("nonce"),
                    versionedRoute.getTyped("to", ::VersionedIdentity))

    init {
        require(nonce.size == NONCE_SIZE)
    }

    companion object {
        val routeEntrySchema: Schema = Schema.Parser()
                .addTypes(mapOf(VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema))
                .parse(RouteEntry::class.java.getResourceAsStream("/uk/co/nesbit/network/api/routing/routeentry.avsc"))

        fun deserialize(bytes: ByteArray): RouteEntry {
            val routeEntryRecord = routeEntrySchema.deserialize(bytes)
            return RouteEntry(routeEntryRecord)
        }
    }

    fun verify(from: VersionedIdentity, signature: DigitalSignature): VersionedRoute {
        require(nonce.size == NONCE_SIZE) { "Bad Nonce" }
        val versionedRoute = VersionedRoute(nonce, from, to)
        val serializedRoute = versionedRoute.serialize()
        signature.verify(to.identity.signingPublicKey, serializedRoute)
        return versionedRoute
    }

    override fun toGenericRecord(): GenericRecord {
        val routeEntryRecord = GenericData.Record(routeEntrySchema)
        routeEntryRecord.putTyped("nonce", nonce)
        routeEntryRecord.putTyped("to", to)
        return routeEntryRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RouteEntry

        if (!Arrays.equals(nonce, other.nonce)) return false
        if (to != other.to) return false

        return true
    }

    override fun hashCode(): Int {
        var result = Arrays.hashCode(nonce)
        result = 31 * result + to.hashCode()
        return result
    }
}

data class SignedEntry(val routeEntry: RouteEntry, val signature: DigitalSignature)

