package uk.co.nesbit.network.api.routing

import org.apache.avro.Schema
import org.apache.avro.SchemaNormalization
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getObjectArray
import uk.co.nesbit.avro.putObjectArray
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity

class ReplyPath(val path: List<SphinxPublicIdentity>) : AvroConvertible {
    constructor(replyPath: GenericRecord) :
            this(replyPath.getObjectArray("path", ::SphinxPublicIdentity))

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val replyPathSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/routing/replypath.avsc"))

        private val schemaFingerprint: ByteArray = SchemaNormalization.parsingFingerprint("SHA-256", replyPathSchema)

        fun deserialize(bytes: ByteArray): ReplyPath {
            val replyPathRecord = replyPathSchema.deserialize(bytes)
            return ReplyPath(replyPathRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val replyPathRecord = GenericData.Record(replyPathSchema)
        replyPathRecord.putObjectArray("path", path)
        return replyPathRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ReplyPath

        if (path != other.path) return false

        return true
    }

    override fun hashCode(): Int {
        return path.hashCode()
    }


}