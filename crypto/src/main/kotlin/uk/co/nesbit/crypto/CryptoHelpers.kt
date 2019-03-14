package uk.co.nesbit.crypto

import djb.Curve25519
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
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
    return ProviderCache.withKeyPairGeneratorInstance("EC") {
        val ecSpec = ECGenParameterSpec("secp256r1")
        initialize(ecSpec, secureRandom)
        generateKeyPair()
    }
}

fun generateRSAKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    return ProviderCache.withKeyPairGeneratorInstance("RSA") {
        initialize(1024, secureRandom)
        generateKeyPair()
    }
}

fun generateECDHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    return ProviderCache.withKeyPairGeneratorInstance("EC") {
        val ecSpec = ECGenParameterSpec("secp256r1")
        initialize(ecSpec, secureRandom)
        generateKeyPair()
    }
}

fun generateDHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    return ProviderCache.withKeyPairGeneratorInstance("DiffieHellman") {
        initialize(1024, secureRandom)
        generateKeyPair()
    }
}

fun generateCurve25519DHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val privateKeyBytes = ByteArray(Curve25519.KEY_SIZE)
    val publicKeyBytes = ByteArray(Curve25519.KEY_SIZE)
    secureRandom.nextBytes(privateKeyBytes)
    Curve25519.keygen(publicKeyBytes, null, privateKeyBytes)
    return KeyPair(Curve25519PublicKey(publicKeyBytes), Curve25519PrivateKey(privateKeyBytes))
}

fun KeyPair.sign(bytes: ByteArray): DigitalSignatureAndKey {
    when (this.private.algorithm) {
        "EC" -> {
            return ProviderCache.withSignatureInstance("SHA256withECDSA") {
                initSign(private)
                update(bytes)
                val sig = sign()
                DigitalSignatureAndKey(algorithm, sig, public)
            }
        }
        "RSA" -> {
            return ProviderCache.withSignatureInstance("SHA256withRSA") {
                initSign(private)
                update(bytes)
                val sig = sign()
                DigitalSignatureAndKey(algorithm, sig, public)
            }
        }
        "EdDSA" -> {
              return ProviderCache.withEdDSAEngine {
                  initSign(private)
                  update(bytes)
                  val sig = sign()
                  DigitalSignatureAndKey(algorithm, sig, public)
              }

        }
        else -> throw NotImplementedError("Can't handle algorithm ${this.private.algorithm}")
    }
}

fun KeyPair.sign(hash: SecureHash): DigitalSignatureAndKey {
    require(hash.algorithm == "SHA-256") { "Signing other than SHA-256 not implemented" }
    when (this.private.algorithm) {
        "EC" -> {
            return ProviderCache.withSignatureInstance("NONEwithECDSA") {
                initSign(private)
                update(hash.bytes)
                val sig = sign()
                DigitalSignatureAndKey("SHA256withECDSA", sig, public)
            }
        }
        "RSA" -> {
            return ProviderCache.withSignatureInstance("NONEwithRSA", "SunJCE") {
                initSign(private)
                // Java wraps hash in DER encoded Digest structure before signing
                val bytes = ByteArrayOutputStream()
                bytes.write(byteArrayOf(0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86.toByte(), 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))
                bytes.write(hash.bytes)
                val digest = bytes.toByteArray()
                update(digest)
                val sig = sign()
                DigitalSignatureAndKey("SHA256withRSA", sig, public)
            }
        }
        else -> throw NotImplementedError("Can't handle algorithm ${this.private.algorithm}")
    }
}

fun getSharedDHSecret(localKeys: KeyPair, remotePublicKey: PublicKey): ByteArray = getSharedDHSecret(localKeys.private, remotePublicKey)

fun getSharedDHSecret(localPrivateKey: PrivateKey, remotePublicKey: PublicKey): ByteArray {
    require(remotePublicKey.algorithm == localPrivateKey.algorithm) { "Keys must use the same algorithm" }
    val secret = when (localPrivateKey.algorithm) {
        "EC" -> {
            ProviderCache.withKeyAgreementInstance("ECDH") {
                init(localPrivateKey)
                doPhase(remotePublicKey, true)
                generateSecret()
            }
        }
        "DH" -> {
            ProviderCache.withKeyAgreementInstance("DH") {
                init(localPrivateKey)
                doPhase(remotePublicKey, true)
                generateSecret()
            }
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
    return ProviderCache.withMacInstance("HmacSHA256") {
        val hmacKey = SecretKeySpec(privateKey, "HmacSHA256")
        init(hmacKey)
        update(data)
        SecureHash("HmacSHA256", doFinal())
    }
}
