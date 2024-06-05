package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.avro.SchemaRegistry.Companion.FingerprintHash
import uk.co.nesbit.utils.decodeHex
import uk.co.nesbit.utils.printHexBinary
import java.util.*
import kotlin.experimental.xor

data class SecureHash(val algorithm: String, val bytes: ByteArray) : AvroConvertible, Comparable<SecureHash> {
    constructor(hashRecord: GenericRecord) :
            this(
                hashRecord.getTyped("algorithm"),
                hashRecord.getTyped("bytes")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val secureHashSchema: Schema = Schema.Parser()
            .parse(javaClass.enclosingClass.getResourceAsStream("securehash.avsc"))

        fun secureHash(bytes: ByteArray, algorithm: String = "SHA-256"): SecureHash {
            return ProviderCache.withMessageDigestInstance(algorithm) {
                SecureHash(algorithm, digest(bytes))
            }
        }

        fun doubleHash(bytes: ByteArray, algorithm: String = "SHA-256"): SecureHash {
            return ProviderCache.withMessageDigestInstance(algorithm) {
                val firstHash = digest(bytes)
                SecureHash(algorithm, digest(firstHash))
            }
        }

        fun secureHash(str: String, algorithm: String = "SHA-256") =
            secureHash(str.toByteArray(Charsets.UTF_8), algorithm)

        fun deserialize(bytes: ByteArray): SecureHash {
            val hashRecord = secureHashSchema.deserialize(bytes)
            return SecureHash(hashRecord)
        }

        fun deserializeJSON(json: String): SecureHash {
            val hashRecord = secureHashSchema.deserializeJSON(json)
            return SecureHash(hashRecord)
        }

        fun parse(str: String): SecureHash {
            require(str.last() == ']') {
                "$str not a valid format expected <algorithm>[<hex bytes>]"
            }
            val algEndIndex = str.indexOf("[")
            require(algEndIndex > 0 && algEndIndex < str.length - 1) {
                "$str not a valid format expected <algorithm>[<hex bytes>]"
            }
            val algorithm = str.substring(0, algEndIndex)
            val bytes = str.substring(algEndIndex + 1, str.length - 1).decodeHex()
            return SecureHash(algorithm, bytes)
        }

        val EMPTY_HASH = secureHash(ByteArray(0))

        @JvmStatic
        fun xorDistance(x: SecureHash, y: SecureHash): Int {
            require(x.algorithm == y.algorithm) { "Hashes must be of same type" }
            val xb = x.bytes
            val yb = y.bytes
            var dist = xb.size * 8
            for (i in xb.indices) {
                if (xb[i] == yb[i]) {
                    dist -= 8
                } else {
                    val xorx = Integer.numberOfLeadingZeros(java.lang.Byte.toUnsignedInt(xb[i] xor yb[i]))
                    return dist - xorx + 24
                }
            }
            return dist
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
        if (!Arrays.equals(bytes, other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(bytes) + 31 * algorithm.hashCode()
    }

    override fun toString(): String = "$algorithm[${bytes.printHexBinary()}]"

    override fun compareTo(other: SecureHash): Int {
        var i = 0
        while (i < bytes.size && i < other.bytes.size) {
            val x = bytes[i].toInt() and 0xFF
            val y = other.bytes[i].toInt() and 0xFF
            if (x < y) {
                return -1
            } else if (x > y) {
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

// Can't put on SchemaRegistry directly due to circular build between modules
fun SchemaRegistry.getSchemaByHash(schemaId: SecureHash): Schema? {
    require(schemaId.algorithm == FingerprintHash)
    return getSchema(schemaId.bytes)
}