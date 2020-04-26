package uk.co.nesbit.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object Ecies {
    private val MAGIC_CONST1 = "ECIES Magic Bits".toByteArray(Charsets.UTF_8)
    private val MAGIC_CONST2 = "ECIES SALT".toByteArray(Charsets.UTF_8)
    private const val PUBLIC_KEY_SIZE = 32 // in bytes
    private const val GCM_KEY_SIZE = 32 // in bytes
    private const val GCM_NONCE_LENGTH = 12 // in bytes
    private const val GCM_TAG_LENGTH = 16 // in bytes

    private fun generateKeys(
        sharedSecret: ByteArray,
        senderEphemeralPublicKey: PublicKey,
        targetPublicKey: PublicKey
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
        return Pair(aesKey, aesNonce)
    }

    fun encryptMessage(
        message: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        random: SecureRandom = newSecureRandom()
    ): ByteArray {
        val aadToEncode = aad ?: ByteArray(0)
        val ephemeralKeyPair = generateCurve25519DHKeyPair(random)
        val sharedSecret = getSharedDHSecret(ephemeralKeyPair, targetPublicKey)
        val (aesKey, aesNonce) = generateKeys(sharedSecret, ephemeralKeyPair.public, targetPublicKey)
        return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
            val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, aesNonce)
            init(Cipher.ENCRYPT_MODE, aesKey, spec)
            updateAAD(aadToEncode)
            concatByteArrays(ephemeralKeyPair.public.encoded, doFinal(message))
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
        require(encryptedMessage.size >= PUBLIC_KEY_SIZE + GCM_TAG_LENGTH) {
            "Illegal length message"
        }
        val messageAndTagSize = encryptedMessage.size - PUBLIC_KEY_SIZE
        val splits = encryptedMessage.splitByteArrays(PUBLIC_KEY_SIZE, messageAndTagSize)
        val dhEmphemeralPublicKey = Curve25519PublicKey(splits[0])
        val ciphertextAndTag = splits[1]
        val aadToValidate = aad ?: ByteArray(0)
        val sharedSecret = dhFunction(dhEmphemeralPublicKey)
        val (aesKey, aesNonce) = generateKeys(sharedSecret, dhEmphemeralPublicKey, targetPublicKey)
        return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
            val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, aesNonce)
            init(Cipher.DECRYPT_MODE, aesKey, spec)
            updateAAD(aadToValidate)
            doFinal(ciphertextAndTag)
        }
    }
}