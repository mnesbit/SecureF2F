package com.nesbit.crypto.sphinx

import com.nesbit.crypto.Curve25519PublicKey
import com.nesbit.crypto.concatByteArrays
import djb.Curve25519
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


object Sphinx {
    private val ZERO_16 = ByteArray(16)
    private val ZERO_32 = ByteArray(32)
    private val HKDF_SALT = "SphinxHashes".toByteArray(Charsets.UTF_8)
    private val SECURITY_PARAMETER = 16 // To work with Curve25519 key (32 bytes each) and 128 bit keys
    private val RHO_KEY_SIZE = 128 // in bits
    private val GCM_KEY_SIZE = 128 // in bits
    private val GCM_NONCE_LENGTH = 12 // in bytes
    private val GCM_TAG_LENGTH = SECURITY_PARAMETER // in bytes
    private val BLIND_LENGTH = Curve25519.KEY_SIZE // in bytes

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun rho(rhoKey: ByteArray, outputSize: Int): ByteArray {
        val streamOutput = ByteArray(outputSize)
        val secretKey = SecretKeySpec(rhoKey, "AES")
        val aesCipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE")
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(ZERO_16))
        return aesCipher.doFinal(streamOutput)
    }

    fun encryptPayload(key: ByteArray, nonce: ByteArray, header: ByteArray, payload: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        cipher.updateAAD(header)
        val cipherText = cipher.doFinal(payload)
        val tag = Arrays.copyOfRange(cipherText, payload.size, payload.size + GCM_TAG_LENGTH)
        val newPayload = Arrays.copyOf(cipherText, payload.size)
        return Pair(newPayload, tag)
    }

    fun decryptPayload(key: ByteArray, nonce: ByteArray, header: ByteArray, tag: ByteArray, payload: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        cipher.updateAAD(header)
        val cipherText = concatByteArrays(payload, tag)
        val decrypted = cipher.doFinal(cipherText)
        return decrypted
    }

    class DerivedHashes(publicKey: Curve25519PublicKey, sharedSecret: ByteArray) {
        companion object {
            val TOTAL_KEY_BYTES = RHO_KEY_SIZE + GCM_NONCE_LENGTH + (GCM_KEY_SIZE / 8) + BLIND_LENGTH
        }

        val rhoKey: ByteArray
        val gcmNonce: ByteArray
        val gcmKey: ByteArray
        val blind: ByteArray

        init {
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            hkdf.init(HKDFParameters(sharedSecret, HKDF_SALT, publicKey.keyBytes))
            val hkdfKey = ByteArray(TOTAL_KEY_BYTES)
            hkdf.generateBytes(hkdfKey, 0, TOTAL_KEY_BYTES)
            var start = 0
            var end = RHO_KEY_SIZE
            rhoKey = Arrays.copyOfRange(hkdfKey, start, end)
            start = end
            end += GCM_NONCE_LENGTH
            gcmNonce = Arrays.copyOfRange(hkdfKey, start, end)
            start = end
            end += (GCM_KEY_SIZE / 8)
            gcmKey = Arrays.copyOfRange(hkdfKey, start, end)
            start = end
            end += BLIND_LENGTH
            blind = Arrays.copyOfRange(hkdfKey, start, end)
            Curve25519.clamp(blind)
        }
    }
}