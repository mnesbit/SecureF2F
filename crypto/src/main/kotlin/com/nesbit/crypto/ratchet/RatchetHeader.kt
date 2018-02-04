package com.nesbit.crypto.ratchet

import com.nesbit.avro.AvroConvertible
import com.nesbit.avro.deserialize
import com.nesbit.avro.getTyped
import com.nesbit.avro.putTyped
import com.nesbit.crypto.PublicKeyHelper
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.PublicKey

class RatchetHeader(val senderDHKey: PublicKey,
                    val previousChainCount: Int,
                    val sequenceNumber: Int) : AvroConvertible {
    constructor(ratchetHeaderRecord: GenericRecord) :
            this(ratchetHeaderRecord.getTyped("senderDHKey"),
                    ratchetHeaderRecord.getTyped("previousChainCount"),
                    ratchetHeaderRecord.getTyped("sequenceNumber"))

    companion object {
        val ratchetHeaderSchema: Schema = Schema.Parser().addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema)).parse(RatchetHeader::class.java.getResourceAsStream("/com/nesbit/crypto/ratchet/ratchetheader.avsc"))

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