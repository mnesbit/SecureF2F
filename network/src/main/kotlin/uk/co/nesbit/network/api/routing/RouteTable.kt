package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getObjectArray
import uk.co.nesbit.avro.putObjectArray

class RouteTable(val allRoutes: List<Routes>) : AvroConvertible {
    constructor(routeTable: GenericRecord) :
            this(routeTable.getObjectArray("allRoutes", ::Routes))

    companion object {
        val routeTableSchema: Schema = Schema.Parser()
                .addTypes(mapOf(Routes.routesSchema.fullName to Routes.routesSchema))
                .parse(RouteTable::class.java.getResourceAsStream("/uk/co/nesbit/network/api/routing/routetable.avsc"))

        fun deserialize(bytes: ByteArray): RouteTable {
            val routeTableRecord = routeTableSchema.deserialize(bytes)
            return RouteTable(routeTableRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val routeTableRecord = GenericData.Record(routeTableSchema)
        routeTableRecord.putObjectArray("allRoutes", allRoutes)
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

