package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.utils.printHexBinary
import java.util.*

data class SecureHash(val algorithm: String, val bytes: ByteArray) : AvroConvertible, Comparable<SecureHash> {
    constructor(hashRecord: GenericRecord) :
            this(hashRecord.getTyped("algorithm"),
                    hashRecord.getTyped("bytes"))

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val secureHashSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("securehash.avsc"))

        fun secureHash(bytes: ByteArray, algorithm: String = "SHA-256"): SecureHash {
            return ProviderCache.withMessageDigestInstance(algorithm) {
                SecureHash(algorithm, digest(bytes))
            }
        }
        fun secureHash(str: String, algorithm: String = "SHA-256") = secureHash(str.toByteArray(Charsets.UTF_8), algorithm)

        fun deserialize(bytes: ByteArray): SecureHash {
            val hashRecord = secureHashSchema.deserialize(bytes)
            return SecureHash(hashRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val record = GenericData.Record(secureHashSchema)
        record.putTyped("algorithm", algorithm)
        record.putTyped("bytes", bytes)
        return record
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false

        other as SecureHash
        if (algorithm != other.algorithm) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(bytes, other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(bytes) + 31 * algorithm.hashCode()
    }

    override fun toString(): String = "$algorithm[${bytes.printHexBinary()}]"

    override fun compareTo(other: SecureHash): Int {
        var i = 0
        while (i < bytes.size && i < other.bytes.size) {
            if (bytes[i] < other.bytes[i]) {
                return -1
            } else if (bytes[i] > other.bytes[i]) {
                return 1
            }
            ++i
        }
        if (bytes.size < other.bytes.size) {
            return -1
        } else if (bytes.size > other.bytes.size) {
            return 1
        }
        return 0
    }
}

fun ByteArray.secureHash(algorithm: String = "SHA-256") = SecureHash.secureHash(this, algorithm)
