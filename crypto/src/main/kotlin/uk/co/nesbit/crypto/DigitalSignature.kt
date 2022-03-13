package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import uk.co.nesbit.avro.AvroConvertible
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.utils.printHexBinary
import java.io.ByteArrayOutputStream
import java.security.PublicKey
import java.security.SignatureException
import java.util.*

class DigitalSignature(val signatureAlgorithm: String,
                       val signature: ByteArray) : AvroConvertible {
    constructor(signatureRecord: GenericRecord) :
            this(signatureRecord.getTyped("signatureAlgorithm"),
                    signatureRecord.getTyped("signature"))

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val digitalSignatureSchema: Schema = Schema.Parser()
                .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/digitalsignature.avsc"))

        fun deserialize(bytes: ByteArray): DigitalSignature {
            val signatureRecord = digitalSignatureSchema.deserialize(bytes)
            return DigitalSignature(signatureRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val signatureRecord = GenericData.Record(digitalSignatureSchema)
        signatureRecord.putTyped("signatureAlgorithm", signatureAlgorithm)
        signatureRecord.putTyped("signature", signature)
        return signatureRecord
    }

    fun toDigitalSignatureAndKey(publicKey: PublicKey): DigitalSignatureAndKey = DigitalSignatureAndKey(signatureAlgorithm, signature, publicKey)

    fun verify(publicKey: PublicKey, bytes: ByteArray) {
        when (this.signatureAlgorithm) {
            "SHA256withECDSA", "SHA256withRSA" -> {
                ProviderCache.withSignatureInstance(signatureAlgorithm) {
                    initVerify(publicKey)
                    update(bytes)
                    if (!verify(signature))
                        throw SignatureException("Signature did not match")
                }
            }
            "Ed25519" -> {
                ProviderCache.withSignatureInstance(signatureAlgorithm, "BC") {
                    if (publicKey is BCEdDSAPublicKey) {
                        initVerify(publicKey)
                    } else if (publicKey is NACLEd25519PublicKey) {
                        initVerify(publicKey.toBCPublicKey())
                    } else {
                        initVerify(publicKey)
                    }
                    update(bytes)
                    if (!verify(signature))
                        throw SignatureException("Signature did not match")
                }
            }
            "NONEwithNACLEd25519" -> {
                val publicKeyBytes = if (publicKey is NACLEd25519PublicKey) {
                    publicKey.keyBytes
                } else if (publicKey is BCEdDSAPublicKey) {
                    (publicKey.toNACLPublicKey() as NACLEd25519PublicKey).keyBytes
                } else throw IllegalArgumentException()
                if (!nacl.cryptoSignVerifyDetached(signature, bytes, bytes.size, publicKeyBytes)) {
                    throw SignatureException("Signature did not match")
                }
            }
            else -> throw NotImplementedError("Can't handle algorithm ${this.signatureAlgorithm}")
        }
    }

    // Note the user MUST check that the PublicKey of this signature is appropriate to the context and typically signed over in the payload
    fun verify(publicKey: PublicKey, hash: SecureHash) {
        when (this.signatureAlgorithm) {
            "SHA256withECDSA" -> {
                ProviderCache.withSignatureInstance("NONEwithECDSA") {
                    initVerify(publicKey)
                    update(hash.bytes)
                    if (!verify(signature))
                        throw SignatureException("Signature did not match")
                }
            }
            "SHA256withRSA" -> {
                ProviderCache.withSignatureInstance("NONEwithRSA", "SunJCE") {
                    initVerify(publicKey)
                    val bytes = ByteArrayOutputStream()
                    // Java wraps hash in DER encoded Digest structure before signing
                    bytes.write(byteArrayOf(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))
                    bytes.write(hash.bytes)
                    val digest = bytes.toByteArray()
                    update(digest)
                    if (!verify(signature))
                        throw SignatureException("Signature did not match")
                }
            }
            else -> throw NotImplementedError("Can't handle algorithm ${this.signatureAlgorithm}")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false

        other as DigitalSignature

        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(signature, other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = signatureAlgorithm.hashCode()
        result = 31 * result + Arrays.hashCode(signature)
        return result
    }

    override fun toString(): String = "$signatureAlgorithm[${signature.printHexBinary()}]"
}