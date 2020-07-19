package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import java.security.PublicKey

class SignedData(
        val data: ByteArray,
        val signature: DigitalSignature
) : AvroConvertible {
    constructor(signedDataRecord: GenericRecord) :
            this(
                    signedDataRecord.getTyped("data"),
                    signedDataRecord.getTyped("signature")
            )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val signedDataSchema: Schema = Schema.Parser()
                .addTypes(mapOf(DigitalSignature.digitalSignatureSchema.fullName to DigitalSignature.digitalSignatureSchema))
                .parse(javaClass.enclosingClass.getResourceAsStream("signeddata.avsc"))

        fun deserialize(bytes: ByteArray): SignedData {
            val hashRecord = signedDataSchema.deserialize(bytes)
            return SignedData(hashRecord)
        }

        fun createSignedData(value: AvroConvertible, signatureProvider: (ByteArray) -> DigitalSignature): SignedData {
            val bytes = value.serialize()
            return SignedData(bytes, signatureProvider(bytes))
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val record = GenericData.Record(signedDataSchema)
        record.putTyped("data", data)
        record.putTyped("signature", signature)
        return record
    }

    fun verify(publicKey: PublicKey) = signature.verify(publicKey, this.data)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SignedData

        if (!data.contentEquals(other.data)) return false
        if (signature != other.signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + signature.hashCode()
        return result
    }
}