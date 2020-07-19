package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.utils.printHexBinary
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
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val digitalSignatureAndKeySchema: Schema = Schema.Parser()
                .addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema))
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/digitalsignatureandkey.avsc"))

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
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(signature, other.signature)) return false
        if (publicKey != other.publicKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signatureAlgorithm.hashCode()
        result = 31 * result + Arrays.hashCode(signature)
        result = 31 * result + publicKey.hashCode()
        return result
    }

    override fun toString(): String = "$signatureAlgorithm($publicKey)[${signature.printHexBinary()}]"
}