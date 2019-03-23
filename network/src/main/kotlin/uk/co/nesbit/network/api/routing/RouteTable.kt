package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.BloomFilter
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.Message

class RouteTable(val fullRoutes: List<Routes>, val knownSources: BloomFilter, val replyTo: SecureHash?) : Message {
    constructor(routeTable: GenericRecord) :
            this(
                routeTable.getObjectArray("fullRoutes", ::Routes),
                routeTable.getTyped("knownSources", ::BloomFilter),
                routeTable.getTyped<SecureHash?>("replyTo", ::SecureHash)
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val routeTableSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    Routes.routesSchema.fullName to Routes.routesSchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema,
                    BloomFilter.bloomFilterSchema.fullName to BloomFilter.bloomFilterSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/routetable.avsc"))

        val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", routeTableSchema)

        fun deserialize(bytes: ByteArray): RouteTable {
            val routeTableRecord = routeTableSchema.deserialize(bytes)
            return RouteTable(routeTableRecord)
        }
    }

    fun verify(): List<VersionedRoute> {
        val versionedRoutes = mutableListOf<VersionedRoute>()
        val uniqueIds = mutableSetOf<SecureHash>()
        for (route in fullRoutes) {
            versionedRoutes.addAll(route.verify())
            uniqueIds += route.from.id
        }
        require(uniqueIds.size == fullRoutes.size) { "All Routes must be from distinct sources" }
        if (replyTo != null) {
            require(replyTo in uniqueIds) { "RouteTable doesn't include self links" }
        }
        return versionedRoutes
    }

    override fun toGenericRecord(): GenericRecord {
        val routeTableRecord = GenericData.Record(routeTableSchema)
        routeTableRecord.putObjectArray("fullRoutes", fullRoutes)
        routeTableRecord.putTyped("knownSources", knownSources)
        routeTableRecord.putTyped("replyTo", replyTo)
        return routeTableRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RouteTable

        if (fullRoutes != other.fullRoutes) return false
        if (knownSources != other.knownSources) return false
        if (replyTo != other.replyTo) return false

        return true
    }

    override fun hashCode(): Int {
        var result = fullRoutes.hashCode()
        result = 31 * result + knownSources.hashCode()
        result = 31 * result + (replyTo?.hashCode() ?: 0)
        return result
    }
}

