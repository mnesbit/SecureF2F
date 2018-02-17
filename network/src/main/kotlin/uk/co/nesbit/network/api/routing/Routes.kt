package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.sphinx.VersionedIdentity

class Routes(val from: VersionedIdentity,
             val entries: List<RouteEntry>,
             val toSignatures: List<DigitalSignature>,
             val fromSignature: DigitalSignature) : AvroConvertible {
    constructor(routes: GenericRecord) :
            this(routes.getTyped("from", ::VersionedIdentity),
                    routes.getObjectArray("entries", ::RouteEntry),
                    routes.getObjectArray("toSignatures", ::DigitalSignature),
                    routes.getTyped("fromSignature", ::DigitalSignature))

    init {
        require(entries.isNotEmpty() && (entries.size == toSignatures.size)) { "Invalid number of route entries" }
    }


    companion object {
        val routesSchema: Schema = Schema.Parser()
                .addTypes(mapOf(VersionedIdentity.versionedIdentitySchema.fullName to VersionedIdentity.versionedIdentitySchema,
                        RouteEntry.routeEntrySchema.fullName to RouteEntry.routeEntrySchema,
                        DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema))
                .parse(Routes::class.java.getResourceAsStream("/uk/co/nesbit/network/api/routing/routes.avsc"))

        fun deserialize(bytes: ByteArray): Routes {
            val routesRecord = routesSchema.deserialize(bytes)
            return Routes(routesRecord)
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

