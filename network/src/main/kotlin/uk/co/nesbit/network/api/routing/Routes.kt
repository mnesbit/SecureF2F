package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.services.KeyService

class Routes(val from: VersionedIdentity,
             val entries: List<RouteEntry>,
             val toSignatures: List<DigitalSignature>,
             val fromSignature: DigitalSignature) : AvroConvertible {
    constructor(routes: GenericRecord) :
            this(
                routes.getTyped("from"),
                routes.getObjectArray("entries", ::RouteEntry),
                routes.getObjectArray("toSignatures", ::DigitalSignature),
                routes.getTyped("fromSignature")
            )

    init {
        require(entries.isNotEmpty() && (entries.size == toSignatures.size)) { "Invalid number of route entries" }
    }


    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val routesSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                    RouteEntry.routeEntrySchema.fullName to RouteEntry.routeEntrySchema,
                    DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/routes.avsc"))

        private val fromSigningSchema: Schema = Schema.createArray(VersionedRoute.versionedRouteSchema)

        fun deserialize(bytes: ByteArray): Routes {
            val routesRecord = routesSchema.deserialize(bytes)
            return Routes(routesRecord)
        }

        fun createRoutes(routes: List<SignedEntry>, fromKeyService: KeyService, fromId: SecureHash): Routes {
            val from = fromKeyService.getVersion(fromId)
            val entries = mutableListOf<RouteEntry>()
            val signatures = mutableListOf<DigitalSignature>()
            val versionedRoutes = GenericData.Array<GenericRecord>(routes.size, fromSigningSchema)
            for ((entry, signature) in routes) {
                val route = entry.toVersionedRoute(from)
                versionedRoutes.add(route.toGenericRecord())
                entries += entry
                signatures += signature
            }
            val serializedRoutes = versionedRoutes.serialize()
            val fromSignature = fromKeyService.sign(fromId, serializedRoutes)
            return Routes(from, entries, signatures, fromSignature.toDigitalSignature())
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val routesRecord = GenericData.Record(routesSchema)
        routesRecord.putTyped("from", from)
        routesRecord.putObjectArray("entries", entries)
        routesRecord.putObjectArray("toSignatures", toSignatures)
        routesRecord.putTyped("fromSignature", fromSignature)
        return routesRecord
    }

    fun verify(): List<VersionedRoute> {
        require(entries.isNotEmpty() && (entries.size == toSignatures.size)) { "Invalid number of route entries" }
        val versionedRoutes = GenericData.Array<GenericRecord>(entries.size, fromSigningSchema)
        val routeList = mutableListOf<VersionedRoute>()
        for (i in 0 until entries.size) {
            val entry = entries[i]
            val route = entry.verify(from, toSignatures[i])
            versionedRoutes.add(route.toGenericRecord())
            routeList += route
        }
        val serializedRoutes = versionedRoutes.serialize()
        fromSignature.verify(from.identity.signingPublicKey, serializedRoutes)
        return routeList
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Routes

        if (from != other.from) return false
        if (entries != other.entries) return false
        if (toSignatures != other.toSignatures) return false
        if (fromSignature != other.fromSignature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = from.hashCode()
        result = 31 * result + entries.hashCode()
        result = 31 * result + toSignatures.hashCode()
        result = 31 * result + fromSignature.hashCode()
        return result
    }
}

