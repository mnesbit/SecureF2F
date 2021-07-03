package uk.co.nesbit.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import uk.co.nesbit.crypto.ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES
import uk.co.nesbit.crypto.ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES
import uk.co.nesbit.crypto.ChaCha20Poly1305.POLY1305_TAG_SIZE
import uk.co.nesbit.crypto.GCMConstants.GCM_KEY_SIZE
import uk.co.nesbit.crypto.GCMConstants.GCM_NONCE_LENGTH
import uk.co.nesbit.crypto.GCMConstants.GCM_TAG_LENGTH
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

object Ecies {
    private val MAGIC_CONST1 = "ECIES Magic Bits".toByteArray(Charsets.UTF_8)
    private val MAGIC_CONST2 = "ECIES SALT".toByteArray(Charsets.UTF_8)
    private const val PUBLIC_KEY_SIZE = 32 // in bytes

    @JvmStatic
    private val counter = AtomicInteger(0)

    private fun generateKeys(
        sharedSecret: ByteArray,
        senderEphemeralPublicKey: PublicKey,
        targetPublicKey: PublicKey,
        countBytes: ByteArray
    ): Pair<SecretKeySpec, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(
            HKDFParameters(
                sharedSecret,
                concatByteArrays(MAGIC_CONST1, senderEphemeralPublicKey.encoded, targetPublicKey.encoded),
                MAGIC_CONST2
            )
        )
        val hkdfKey = ByteArray(GCM_KEY_SIZE + GCM_NONCE_LENGTH)
        hkdf.generateBytes(hkdfKey, 0, hkdfKey.size)
        val splits = hkdfKey.splitByteArrays(
            GCM_KEY_SIZE,
            GCM_NONCE_LENGTH
        )
        val aesKey = SecretKeySpec(splits[0], "AES")
        val aesNonce = splits[1]
        aesNonce[0] = aesNonce[0] xor countBytes[0]
        aesNonce[1] = aesNonce[1] xor countBytes[1]
        aesNonce[2] = aesNonce[2] xor countBytes[2]
        aesNonce[3] = aesNonce[3] xor countBytes[3]
        return Pair(aesKey, aesNonce)
    }

    fun encryptMessage(
        message: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        random: SecureRandom = newSecureRandom()
    ): ByteArray {
        val ephemeralKeyPair = when (targetPublicKey.algorithm) {
            "Curve25519" -> generateCurve25519DHKeyPair(random)
            "NACLCurve25519" -> generateNACLDHKeyPair(random)
            else -> throw IllegalArgumentException("Unsupported Diffie-Hellman algorithm ${targetPublicKey.algorithm}")
        }
        val aadToEncode = concatByteArrays(
            aad
                ?: ByteArray(0), ephemeralKeyPair.public.encoded, targetPublicKey.encoded
        )
        val sharedSecret = getSharedDHSecret(ephemeralKeyPair, targetPublicKey)
        val count = counter.getAndIncrement().toByteArray()
        val (aesKey, aesNonce) = generateKeys(sharedSecret, ephemeralKeyPair.public, targetPublicKey, count)
        return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
            val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, aesNonce)
            init(Cipher.ENCRYPT_MODE, aesKey, spec)
            updateAAD(aadToEncode)
            concatByteArrays(ephemeralKeyPair.public.encoded, count, doFinal(message))
        }
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        nodeKeys: SphinxIdentityKeyPair
    ): ByteArray {
        val dhFunction = { x: PublicKey -> getSharedDHSecret(nodeKeys.diffieHellmanKeys, x) }
        return decryptMessage(encryptedMessage, aad, nodeKeys.diffieHellmanKeys.public, dhFunction)
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        dhFunction: (remotePublicKey: PublicKey) -> ByteArray
    ): ByteArray {
        require(encryptedMessage.size >= PUBLIC_KEY_SIZE + 4 + GCM_TAG_LENGTH) {
            "Illegal length message"
        }
        val messageAndTagSize = encryptedMessage.size - PUBLIC_KEY_SIZE - 4
        val splits = encryptedMessage.splitByteArrays(PUBLIC_KEY_SIZE, Int.SIZE_BYTES, messageAndTagSize)
        val dhEmphemeralPublicKey = when (targetPublicKey.algorithm) {
            "Curve25519" -> Curve25519PublicKey(splits[0])
            "NACLCurve25519" -> NACLCurve25519PublicKey(splits[0])
            else -> throw IllegalArgumentException("Unsupported Diffie-Hellman algorithm")
        }
        val count = splits[1]
        val ciphertextAndTag = splits[2]
        val aadToValidate = concatByteArrays(
            aad
                ?: ByteArray(0), dhEmphemeralPublicKey.encoded, targetPublicKey.encoded
        )
        val sharedSecret = dhFunction(dhEmphemeralPublicKey)
        val (aesKey, aesNonce) = generateKeys(sharedSecret, dhEmphemeralPublicKey, targetPublicKey, count)
        return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
            val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, aesNonce)
            init(Cipher.DECRYPT_MODE, aesKey, spec)
            updateAAD(aadToValidate)
            doFinal(ciphertextAndTag)
        }
    }
}

object EciesChaCha {
    private val MAGIC_CONST1 = "ECIES ChaCha Magic Bits".toByteArray(Charsets.UTF_8)
    private val MAGIC_CONST2 = "ECIES ChaCha SALT".toByteArray(Charsets.UTF_8)
    private const val PUBLIC_KEY_SIZE = 32 // in bytes

    @JvmStatic
    private val counter = AtomicInteger(0)

    private fun generateKeys(
        sharedSecret: ByteArray,
        senderEphemeralPublicKey: PublicKey,
        targetPublicKey: PublicKey,
        countBytes: ByteArray
    ): Pair<ByteArray, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(
            HKDFParameters(
                sharedSecret,
                concatByteArrays(MAGIC_CONST1, senderEphemeralPublicKey.encoded, targetPublicKey.encoded),
                MAGIC_CONST2
            )
        )
        val hkdfKey = ByteArray(CHACHA_KEY_SIZE_BYTES + CHACHA_NONCE_SIZE_BYTES)
        hkdf.generateBytes(hkdfKey, 0, hkdfKey.size)
        val splits = hkdfKey.splitByteArrays(
            CHACHA_KEY_SIZE_BYTES,
            CHACHA_NONCE_SIZE_BYTES
        )
        val chaChaKey = splits[0]
        val chaChaNonce = splits[1]
        chaChaNonce[0] = chaChaNonce[0] xor countBytes[0]
        chaChaNonce[1] = chaChaNonce[1] xor countBytes[1]
        chaChaNonce[2] = chaChaNonce[2] xor countBytes[2]
        chaChaNonce[3] = chaChaNonce[3] xor countBytes[3]
        return Pair(chaChaKey, chaChaNonce)
    }

    fun encryptMessage(
        message: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        random: SecureRandom = newSecureRandom()
    ): ByteArray {
        val ephemeralKeyPair = when (targetPublicKey.algorithm) {
            "Curve25519" -> generateCurve25519DHKeyPair(random)
            "NACLCurve25519" -> generateNACLDHKeyPair(random)
            else -> throw IllegalArgumentException("Unsupported Diffie-Hellman algorithm ${targetPublicKey.algorithm}")
        }
        val aadToEncode = concatByteArrays(
            aad ?: ByteArray(0), ephemeralKeyPair.public.encoded, targetPublicKey.encoded
        )
        val sharedSecret = getSharedDHSecret(ephemeralKeyPair, targetPublicKey)
        val count = counter.getAndIncrement().toByteArray()
        val (chaChaKey, chaChaNonce) = generateKeys(sharedSecret, ephemeralKeyPair.public, targetPublicKey, count)
        return concatByteArrays(
            ephemeralKeyPair.public.encoded,
            count,
            chaChaEncrypt(chaChaKey, chaChaNonce, message, aadToEncode)
        )
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        nodeKeys: SphinxIdentityKeyPair
    ): ByteArray {
        val dhFunction = { x: PublicKey -> getSharedDHSecret(nodeKeys.diffieHellmanKeys, x) }
        return decryptMessage(encryptedMessage, aad, nodeKeys.diffieHellmanKeys.public, dhFunction)
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        dhFunction: (remotePublicKey: PublicKey) -> ByteArray
    ): ByteArray {
        require(encryptedMessage.size >= PUBLIC_KEY_SIZE + 4 + POLY1305_TAG_SIZE) {
            "Illegal length message"
        }
        val messageAndTagSize = encryptedMessage.size - PUBLIC_KEY_SIZE - 4
        val splits = encryptedMessage.splitByteArrays(PUBLIC_KEY_SIZE, Int.SIZE_BYTES, messageAndTagSize)
        val dhEmphemeralPublicKey = when (targetPublicKey.algorithm) {
            "Curve25519" -> Curve25519PublicKey(splits[0])
            "NACLCurve25519" -> NACLCurve25519PublicKey(splits[0])
            else -> throw IllegalArgumentException("Unsupported Diffie-Hellman algorithm")
        }
        val count = splits[1]
        val ciphertextAndTag = splits[2]
        val aadToValidate = concatByteArrays(
            aad
                ?: ByteArray(0), dhEmphemeralPublicKey.encoded, targetPublicKey.encoded
        )
        val sharedSecret = dhFunction(dhEmphemeralPublicKey)
        val (chaChaKey, chaChaNonce) = generateKeys(sharedSecret, dhEmphemeralPublicKey, targetPublicKey, count)
        return chaChaDecrypt(chaChaKey, chaChaNonce, ciphertextAndTag, aadToValidate)
    }
}