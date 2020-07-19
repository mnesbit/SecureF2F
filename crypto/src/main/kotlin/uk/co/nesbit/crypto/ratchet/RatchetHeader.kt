package uk.co.nesbit.crypto.ratchet

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.PublicKeyHelper
import java.security.PublicKey

class RatchetHeader(val senderDHKey: PublicKey,
                    val previousChainCount: Int,
                    val sequenceNumber: Int) : AvroConvertible {
    constructor(ratchetHeaderRecord: GenericRecord) :
            this(ratchetHeaderRecord.getTyped("senderDHKey"),
                    ratchetHeaderRecord.getTyped("previousChainCount"),
                    ratchetHeaderRecord.getTyped("sequenceNumber"))

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val ratchetHeaderSchema: Schema = Schema.Parser()
                .addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema))
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/ratchet/ratchetheader.avsc"))

        fun deserialize(bytes: ByteArray): RatchetHeader {
            val ratchetHeaderRecord = ratchetHeaderSchema.deserialize(bytes)
            return RatchetHeader(ratchetHeaderRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val ratchetHeaderRecord = GenericData.Record(ratchetHeaderSchema)
        ratchetHeaderRecord.putTyped("senderDHKey", senderDHKey)
        ratchetHeaderRecord.putTyped("previousChainCount", previousChainCount)
        ratchetHeaderRecord.putTyped("sequenceNumber", sequenceNumber)
        return ratchetHeaderRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RatchetHeader

        if (senderDHKey != other.senderDHKey) return false
        if (previousChainCount != other.previousChainCount) return false
        if (sequenceNumber != other.sequenceNumber) return false

        return true
    }

    override fun hashCode(): Int {
        var result = senderDHKey.hashCode()
        result = 31 * result + previousChainCount
        result = 31 * result + sequenceNumber
        return result
    }
}