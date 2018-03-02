package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.SecureHash

class RouteTable(val allRoutes: List<Routes>, val replyTo: SecureHash?) : AvroConvertible {
    constructor(routeTable: GenericRecord) :
            this(routeTable.getObjectArray("allRoutes", ::Routes),
                    routeTable.getTyped<SecureHash?>("replyTo", ::SecureHash))

    init {
        val uniqueIds = mutableSetOf<SecureHash>()
        for (route in allRoutes) {
            route.verify()
            uniqueIds += route.from.id
        }
        require(uniqueIds.size == allRoutes.size) { "All Routes must be from distinct sources" }
        if (replyTo != null) {
            require(replyTo in uniqueIds) { "RouteTable doesn't include self links" }
        }
    }

    companion object {
        val routeTableSchema: Schema = Schema.Parser()
                .addTypes(mapOf(Routes.routesSchema.fullName to Routes.routesSchema,
                        SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema))
                .parse(RouteTable::class.java.getResourceAsStream("/uk/co/nesbit/network/api/routing/routetable.avsc"))

        fun deserialize(bytes: ByteArray): RouteTable {
            val routeTableRecord = routeTableSchema.deserialize(bytes)
            return RouteTable(routeTableRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val routeTableRecord = GenericData.Record(routeTableSchema)
        routeTableRecord.putObjectArray("allRoutes", allRoutes)
        routeTableRecord.putTyped("replyTo", replyTo)
        return routeTableRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RouteTable

        if (allRoutes != other.allRoutes) return false

        return true
    }

    override fun hashCode(): Int {
        return allRoutes.hashCode()
    }
}

