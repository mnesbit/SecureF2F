package com.nesbit.crypto

import djb.Curve25519
import net.i2p.crypto.eddsa.EdDSAEngine
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun newSecureRandom(): SecureRandom {
    return if (System.getProperty("os.name") == "Linux") {
        SecureRandom.getInstance("NativePRNGNonBlocking")
    } else {
        SecureRandom.getInstanceStrong()
    }
}

fun generateEdDSAKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val keyGen = net.i2p.crypto.eddsa.KeyPairGenerator()
    keyGen.initialize(256, secureRandom)
    return keyGen.generateKeyPair()
}

fun generateECDSAKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("EC")
    val ecSpec = ECGenParameterSpec("secp256r1")
    keyGen.initialize(ecSpec, secureRandom)
    return keyGen.generateKeyPair()
}

fun generateRSAKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(1024, secureRandom)
    return keyGen.generateKeyPair()
}

fun generateECDHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("EC")
    val ecSpec = ECGenParameterSpec("secp256r1")
    keyGen.initialize(ecSpec, secureRandom)
    return keyGen.generateKeyPair()
}

fun generateDHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("DiffieHellman")
    keyGen.initialize(1024, secureRandom)
    return keyGen.generateKeyPair()
}

fun generateCurve25519DHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val privateKeyBytes = ByteArray(Curve25519.KEY_SIZE)
    val publicKeyBytes = ByteArray(Curve25519.KEY_SIZE)
    secureRandom.nextBytes(privateKeyBytes)
    Curve25519.keygen(publicKeyBytes, null, privateKeyBytes)
    return KeyPair(Curve25519PublicKey(publicKeyBytes), Curve25519PrivateKey(privateKeyBytes))
}

fun KeyPair.sign(bytes: ByteArray): DigitalSignature {
    when (this.private.algorithm) {
        "EC" -> {
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(this.private)
            signer.update(bytes)
            val sig = signer.sign()
            return DigitalSignature(signer.algorithm, sig, this.public)
        }
        "RSA" -> {
            val signer = Signature.getInstance("SHA256withRSA")
            signer.initSign(this.private)
            signer.update(bytes)
            val sig = signer.sign()
            return DigitalSignature(signer.algorithm, sig, this.public)
        }
        "EdDSA" -> {
            val signer = EdDSAEngine()
            signer.initSign(this.private)
            signer.update(bytes)
            val sig = signer.sign()
            return DigitalSignature(signer.algorithm, sig, this.public)
        }
        else -> throw NotImplementedError("Can't handle algorithm ${this.private.algorithm}")
    }
}

fun KeyPair.sign(hash: SecureHash): DigitalSignature {
    require(hash.algorithm == "SHA-256") { "Signing other than SHA-256 not implemented" }
    when (this.private.algorithm) {
        "EC" -> {
            val signer = Signature.getInstance("NONEwithECDSA")
            signer.initSign(this.private)
            signer.update(hash.bytes)
            val sig = signer.sign()
            return DigitalSignature("SHA256withECDSA", sig, this.public)
        }
        "RSA" -> {
            val signer = Signature.getInstance("NONEwithRSA", "SunJCE")
            signer.initSign(this.private)
            // Java wraps hash in DER encoded Digest structure before signing
            val bytes = ByteArrayOutputStream()
            bytes.write(byteArrayOf(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))
            bytes.write(hash.bytes)
            val digest = bytes.toByteArray()
            signer.update(digest)
            val sig = signer.sign()
            return DigitalSignature("SHA256withRSA", sig, this.public)
        }
        else -> throw NotImplementedError("Can't handle algorithm ${this.private.algorithm}")
    }
}

fun getSharedDHSecret(localKeys: KeyPair, remotePublicKey: PublicKey): ByteArray = getSharedDHSecret(localKeys.private, remotePublicKey)

fun getSharedDHSecret(localPrivateKey: PrivateKey, remotePublicKey: PublicKey): ByteArray {
    require(remotePublicKey.algorithm == localPrivateKey.algorithm) { "Keys must use the same algorithm" }
    val secret = when (localPrivateKey.algorithm) {
        "EC" -> {
            val agree = KeyAgreement.getInstance("ECDH")
            agree.init(localPrivateKey)
            agree.doPhase(remotePublicKey, true)
            agree.generateSecret()
        }
        "DH" -> {
            val agree = KeyAgreement.getInstance("DH")
            agree.init(localPrivateKey)
            agree.doPhase(remotePublicKey, true)
            agree.generateSecret()
        }
        "Curve25519" -> {
            val secret = ByteArray(Curve25519.KEY_SIZE)
            Curve25519.curve(secret, localPrivateKey.encoded, remotePublicKey.encoded)
            return secret
        }
        else -> throw NotImplementedError("Can't handle algorithm ${localPrivateKey.algorithm}")
    }
    // Note that this value needs passing into at least a hash, or better a Key Derivation Function along with the context PublicKeys
    return secret
}

fun getHMAC(privateKey: ByteArray, data: ByteArray): SecureHash {
    val hmac = Mac.getInstance("HmacSHA256")
    val hmacKey = SecretKeySpec(privateKey, "HmacSHA256")
    hmac.init(hmacKey)
    hmac.update(data)
    return SecureHash("HmacSHA256", hmac.doFinal())
}
