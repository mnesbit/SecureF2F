package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericArray
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericDatumWriter
import org.apache.avro.generic.GenericRecord
import org.apache.avro.io.EncoderFactory
import uk.co.nesbit.avro.*
import java.io.ByteArrayOutputStream
import java.security.PublicKey

class ThresholdPublicKey(
    val threshold: Int,
    val childKeys: List<PublicKey>
) : PublicKey {
    init {
        require(childKeys.isNotEmpty()) {
            "must have at least one child key"
        }
        require(childKeys.size == childKeys.toSet().size) {
            "No diplicate keys allowed"
        }
        require(threshold > 0 && threshold <= childKeys.size) {
            "invalid threshold $threshold"
        }
    }

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val thresholdPublicKeySchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema
                )
            )
            .parse(javaClass.getResourceAsStream("/uk/co/nesbit/crypto/thresholdpublickey.avsc"))

        fun deserialize(bytes: ByteArray): ThresholdPublicKey {
            val keyRecord = thresholdPublicKeySchema.deserialize(bytes)
            return ThresholdPublicKey(
                keyRecord.getTyped("threshold"),
                keyRecord.getObjectArray("childKeys") { record ->
                    PublicKeyHelper.fromGenericRecord(record)
                }
            )
        }
    }

    override fun getAlgorithm(): String = "ThresholdPublicKey"

    override fun getFormat(): String = "AVRO"

    override fun getEncoded(): ByteArray {
        val keyRecord = GenericData.Record(thresholdPublicKeySchema)
        keyRecord.putTyped("threshold", threshold)
        keyRecord.putGenericArray("childKeys", childKeys.map { it.toGenericRecord() })
        return keyRecord.serialize()
    }

    fun createMultiSig(signatures: List<DigitalSignature>): DigitalSignatureAndKey {
        val arraySchema = Schema.createArray(DigitalSignature.digitalSignatureSchema)
        val signatureArray = GenericData.Array(
            arraySchema,
            signatures.map { it.toGenericRecord() }
        )
        val datumWriter = GenericDatumWriter<GenericArray<GenericRecord>>(signatureArray.schema)
        val arrayBytes = ByteArrayOutputStream().use {
            val encoder = EncoderFactory.get().binaryEncoder(it, null)
            datumWriter.write(signatureArray, encoder)
            encoder.flush()
            it.flush()
            it.toByteArray()
        }
        return DigitalSignatureAndKey("ThresholdSignature", arrayBytes, this)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ThresholdPublicKey

        if (threshold != other.threshold) return false
        if (childKeys != other.childKeys) return false

        return true
    }

    override fun hashCode(): Int {
        var result = threshold
        result = 31 * result + childKeys.hashCode()
        return result
    }

}