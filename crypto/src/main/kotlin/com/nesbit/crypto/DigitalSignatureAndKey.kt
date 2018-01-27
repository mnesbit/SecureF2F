package com.nesbit.crypto

import com.nesbit.avro.AvroConvertible
import com.nesbit.avro.deserialize
import com.nesbit.avro.getTyped
import com.nesbit.avro.putTyped
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.PublicKey
import java.util.*

class DigitalSignatureAndKey(val signatureAlgorithm: String,
                             val signature: ByteArray,
                             val publicKey: PublicKey) : AvroConvertible {
    constructor(signatureRecord: GenericRecord) :
            this(signatureRecord.getTyped("signatureAlgorithm"),
                    signatureRecord.getTyped("signature"),
                    signatureRecord.getTyped("publicKey"))

    companion object {
        val digitalSignatureAndKeySchema: Schema = Schema.Parser().addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema)).parse(DigitalSignatureAndKey::class.java.getResourceAsStream("/com/nesbit/crypto/digitalsignatureandkey.avsc"))

        fun deserialize(bytes: ByteArray): DigitalSignatureAndKey {
            val signatureRecord = digitalSignatureAndKeySchema.deserialize(bytes)
            return DigitalSignatureAndKey(signatureRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(digitalSignatureAndKeySchema)
        signatureRecord.putTyped("signatureAlgorithm", signatureAlgorithm)
        signatureRecord.putTyped("signature", signature)
        signatureRecord.putTyped("publicKey", publicKey.toGenericRecord())
        return signatureRecord
    }

    fun toDigitalSignature(): DigitalSignature = DigitalSignature(signatureAlgorithm, signature)

    // Note the user MUST check that the PublicKey of this signature is appropriate to the context and typically signed over in the payload
    fun verify(bytes: ByteArray) = toDigitalSignature().verify(publicKey, bytes)

    // Note the user MUST check that the PublicKey of this signature is appropriate to the context and typically signed over in the payload
    fun verify(hash: SecureHash) = toDigitalSignature().verify(publicKey, hash)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false

        other as DigitalSignatureAndKey

        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!Arrays.equals(signature, other.signature)) return false
        if (publicKey != other.publicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signatureAlgorithm.hashCode()
        result = 31 * result + Arrays.hashCode(signature)
        result = 31 * result + publicKey.hashCode()
        return result
    }

    override fun toString(): String = "$signatureAlgorithm($publicKey)[${signature.printHex()}]"
}