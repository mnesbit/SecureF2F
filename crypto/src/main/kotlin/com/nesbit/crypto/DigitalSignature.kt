package com.nesbit.crypto

import net.i2p.crypto.eddsa.EdDSAEngine
import java.io.ByteArrayOutputStream
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.util.*

class DigitalSignature(val signatureAlgorithm: String,
                       val signature: ByteArray,
                       val publicKey: PublicKey) {
    // Note the user MUST check that the PublicKey of this signature is appropriate to the context and typically signed over in the payload
    fun verify(bits: ByteArray) {
        when (this.signatureAlgorithm) {
            "SHA256withECDSA", "SHA256withRSA" -> {
                val verifier = Signature.getInstance(this.signatureAlgorithm)
                verifier.initVerify(this.publicKey)
                verifier.update(bits)
                if (verifier.verify(this.signature) == false)
                    throw SignatureException("Signature did not match")
            }
            "NONEwithEdDSA" -> {
                val verifier = EdDSAEngine()
                require(this.signatureAlgorithm == verifier.algorithm) { "Signature algorithm not EdDSA" }
                verifier.initVerify(this.publicKey)
                verifier.update(bits)
                if (verifier.verify(this.signature) == false)
                    throw SignatureException("Signature did not match")
            }
            else -> throw NotImplementedError("Can't handle algorithm ${this.signatureAlgorithm}")
        }
    }

    // Note the user MUST check that the PublicKey of this signature is appropriate to the context and typically signed over in the payload
    fun verify(hash: SecureHash) {
        when (this.signatureAlgorithm) {
            "SHA256withECDSA" -> {
                val verifier = Signature.getInstance("NONEwithECDSA")
                verifier.initVerify(this.publicKey)
                verifier.update(hash.bytes)
                if (verifier.verify(this.signature) == false)
                    throw SignatureException("Signature did not match")
            }
            "SHA256withRSA" -> {
                val verifier = Signature.getInstance("NONEwithRSA", "SunJCE")
                verifier.initVerify(this.publicKey)
                val bits = ByteArrayOutputStream()
                // Java wraps hash in DER encoded Digest structure before signing
                bits.write(byteArrayOf(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))
                bits.write(hash.bytes)
                val digest = bits.toByteArray()
                verifier.update(digest)
                if (verifier.verify(this.signature) == false)
                    throw SignatureException("Signature did not match")
            }
            else -> throw NotImplementedError("Can't handle algorithm ${this.signatureAlgorithm}")
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false

        other as DigitalSignature

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