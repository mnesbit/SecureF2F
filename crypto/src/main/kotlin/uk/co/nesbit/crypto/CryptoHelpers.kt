package uk.co.nesbit.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.interfaces.DiffieHellman
import com.goterl.lazysodium.interfaces.DiffieHellman.SCALARMULT_CURVE25519_BYTES
import com.goterl.lazysodium.interfaces.DiffieHellman.SCALARMULT_CURVE25519_SCALARBYTES
import com.goterl.lazysodium.interfaces.Sign
import djb.Curve25519
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec
import java.io.ByteArrayOutputStream
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

val nacl: Sign.Native = LazySodiumJava(SodiumJava())
val naclDH: DiffieHellman.Native = LazySodiumJava(SodiumJava())

object GCMConstants {
    const val GCM_KEY_SIZE = 32 // in bytes
    const val GCM_NONCE_LENGTH = 12 // in bytes
    const val GCM_TAG_LENGTH = 16 // in bytes
}

fun newSecureRandom(): SecureRandom {
    return SecureRandom.getInstance(
        "DRBG",
        DrbgParameters.instantiation(256, DrbgParameters.Capability.PR_AND_RESEED, "random enough?".toByteArray())
    )
}

fun generateEdDSAKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    return ProviderCache.withKeyPairGeneratorInstance("Ed25519", "BC") {
        val ecSpec = EdDSAParameterSpec(EdDSAParameterSpec.Ed25519)
        initialize(ecSpec, secureRandom)
        generateKeyPair()
    }

}

fun generateECDSAKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    return ProviderCache.withKeyPairGeneratorInstance("EC") {
        val ecSpec = ECGenParameterSpec("secp256r1")
        initialize(ecSpec, secureRandom)
        generateKeyPair()
    }
}

fun generateNACLKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val seed = ByteArray(Sign.ED25519_SEEDBYTES)
    secureRandom.nextBytes(seed)
    val publicKeyBytes = ByteArray(Sign.ED25519_PUBLICKEYBYTES)
    val secretKey = ByteArray(Sign.ED25519_SECRETKEYBYTES)
    nacl.cryptoSignSeedKeypair(publicKeyBytes, secretKey, seed)
    val privateKey = NACLEd25519PrivateKey(seed)
    val publicKey = NACLEd25519PublicKey(publicKeyBytes)
    return KeyPair(publicKey, privateKey)
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

fun generateNACLDHKeyPair(secureRandom: SecureRandom = newSecureRandom()): KeyPair {
    val privateKeyBytes = ByteArray(SCALARMULT_CURVE25519_SCALARBYTES)
    val publicKeyBytes = ByteArray(SCALARMULT_CURVE25519_BYTES)
    secureRandom.nextBytes(privateKeyBytes)
    naclDH.cryptoScalarMultBase(publicKeyBytes, privateKeyBytes)
    return KeyPair(NACLCurve25519PublicKey(publicKeyBytes), NACLCurve25519PrivateKey(privateKeyBytes))
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
        "Ed25519" -> {
            return ProviderCache.withSignatureInstance("Ed25519", "BC") {
                initSign(private)
                update(bytes)
                val sig = sign()
                DigitalSignatureAndKey(algorithm, sig, public)
            }
        }
        "NACLEd25519" -> {
            val naclPublicKey = ByteArray(Sign.PUBLICKEYBYTES)
            val naclSecretKey = ByteArray(Sign.SECRETKEYBYTES)
            nacl.cryptoSignSeedKeypair(naclPublicKey, naclSecretKey, private.encoded)
            val signature = ByteArray(Sign.BYTES)
            nacl.cryptoSignDetached(signature, bytes, bytes.size.toLong(), naclSecretKey)
            return DigitalSignatureAndKey("NONEwithNACLEd25519", signature, public)
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
        "NACLCurve25519" -> {
            val secret = ByteArray(SCALARMULT_CURVE25519_BYTES)
            naclDH.cryptoScalarMult(secret, localPrivateKey.encoded, remotePublicKey.encoded)
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

fun aesGCMEncryptMessage(
    key: ByteArray,
    secureRandom: SecureRandom = newSecureRandom(),
    plainText: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == GCMConstants.GCM_KEY_SIZE) {
        "GCM key must be 32 bytes"
    }
    val aesNonce = ByteArray(GCMConstants.GCM_NONCE_LENGTH)
    secureRandom.nextBytes(aesNonce)
    return concatByteArrays(aesNonce, aesGCMEncrypt(key, aesNonce, plainText, aad))
}

fun aesGCMEncrypt(
    key: ByteArray,
    aesNonce: ByteArray,
    plainText: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == GCMConstants.GCM_KEY_SIZE) {
        "GCM key must be 32 bytes"
    }
    require(aesNonce.size == GCMConstants.GCM_NONCE_LENGTH) {
        "GCM nonce must be 12 bytes"
    }
    val aesKey = SecretKeySpec(key, "AES")
    return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
        val spec = GCMParameterSpec(GCMConstants.GCM_TAG_LENGTH * 8, aesNonce)
        init(Cipher.ENCRYPT_MODE, aesKey, spec)
        if (aad != null) {
            updateAAD(aad)
        }
        doFinal(plainText)
    }
}

fun aesGCMDecryptMessage(
    key: ByteArray,
    cipherTextNonceAndTag: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == GCMConstants.GCM_KEY_SIZE) {
        "GCM key must be 32 bytes"
    }
    val splits =
        cipherTextNonceAndTag.splitByteArrays(
            GCMConstants.GCM_NONCE_LENGTH,
            cipherTextNonceAndTag.size - GCMConstants.GCM_NONCE_LENGTH
        )
    val aesNonce = splits[0]
    val cipherTextAndTag = splits[1]
    return aesGCMDecrypt(key, aesNonce, cipherTextAndTag, aad)
}

fun aesGCMDecrypt(
    key: ByteArray,
    aesNonce: ByteArray,
    cipherTextAndTag: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == GCMConstants.GCM_KEY_SIZE) {
        "GCM key must be 32 bytes"
    }
    require(aesNonce.size == GCMConstants.GCM_NONCE_LENGTH) {
        "GCM nonce must be 12 bytes"
    }
    val aesKey = SecretKeySpec(key, "AES")
    return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
        val spec = GCMParameterSpec(GCMConstants.GCM_TAG_LENGTH * 8, aesNonce)
        init(Cipher.DECRYPT_MODE, aesKey, spec)
        if (aad != null) {
            updateAAD(aad)
        }
        doFinal(cipherTextAndTag)
    }
}

fun chaChaEncryptMessage(
    key: ByteArray,
    secureRandom: SecureRandom = newSecureRandom(),
    plainText: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES) {
        "ChaCha20-Poly1305 key must be 32 bytes"
    }
    val chaChaNonce = ByteArray(ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES)
    secureRandom.nextBytes(chaChaNonce)
    return concatByteArrays(chaChaNonce, chaChaEncrypt(key, chaChaNonce, plainText, aad))
}

fun chaChaEncrypt(
    key: ByteArray,
    chaChaNonce: ByteArray,
    plainText: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES) {
        "ChaCha20-Poly1305 key must be 32 bytes"
    }
    require(chaChaNonce.size == ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES) {
        "ChaCha20-Poly1305 nonce must be 12 bytes"
    }
    val encrypter = ChaCha20Poly1305.Encode(ParametersWithIV(KeyParameter(key), chaChaNonce))
    return encrypter.encodeCiphertext(plainText, aad)
}

fun chaChaDecryptMessage(
    key: ByteArray,
    cipherTextNonceAndTag: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES) {
        "ChaCha20-Poly1305 key must be 32 bytes"
    }
    val splits = cipherTextNonceAndTag.splitByteArrays(
        ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES,
        cipherTextNonceAndTag.size - ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES
    )
    val chaChaNonce = splits[0]
    val cipherTextAndTag = splits[1]
    return chaChaDecrypt(key, chaChaNonce, cipherTextAndTag, aad)
}

fun chaChaDecrypt(
    key: ByteArray,
    chaChaNonce: ByteArray,
    cipherTextAndTag: ByteArray,
    aad: ByteArray? = null
): ByteArray {
    require(key.size == ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES) {
        "ChaCha20-Poly1305 key must be 32 bytes"
    }
    require(chaChaNonce.size == ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES) {
        "ChaCha20-Poly1305 nonce must be 12 bytes"
    }
    val decrypter = ChaCha20Poly1305.Decode(ParametersWithIV(KeyParameter(key), chaChaNonce))
    return decrypter.decodeCiphertext(cipherTextAndTag, aad)
}

