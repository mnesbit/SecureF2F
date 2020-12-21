package uk.co.nesbit.network.api.groups

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.crypto.PublicKeyHelper
import uk.co.nesbit.crypto.SecureHash
import java.security.PublicKey
import java.time.Instant

data class HistoricKeyInfo(
    val key: PublicKey,
    val validFrom: Instant,
    val validUntil: Instant
) : AvroConvertible {
    constructor(historicKeyInfoRecord: GenericRecord) : this(
        historicKeyInfoRecord.getTyped("key"),
        historicKeyInfoRecord.getTyped("validFrom"),
        historicKeyInfoRecord.getTyped("validUntil"),
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val historicKeyInfoSchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/network/api/groups/historickeyinfo.avsc"))

        fun deserialize(bytes: ByteArray): HistoricKeyInfo {
            val historicKeyInfoRecord = historicKeyInfoSchema.deserialize(bytes)
            return HistoricKeyInfo(historicKeyInfoRecord)
        }
    }

    val keyId: SecureHash by lazy {
        SecureHash.secureHash(key.encoded)
    }

    override fun toGenericRecord(): GenericRecord {
        val historicKeyInfoRecord = GenericData.Record(historicKeyInfoSchema)
        historicKeyInfoRecord.putTyped("key", key)
        historicKeyInfoRecord.putTyped("validFrom", validFrom)
        historicKeyInfoRecord.putTyped("validUntil", validUntil)
        return historicKeyInfoRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as HistoricKeyInfo

        if (key != other.key) return false
        if (validFrom != other.validFrom) return false
        if (validUntil != other.validUntil) return false

        return true
    }

    override fun hashCode(): Int {
        var result = key.hashCode()
        result = 31 * result + validFrom.hashCode()
        result = 31 * result + validUntil.hashCode()
        return result
    }

}