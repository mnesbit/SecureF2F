package com.nesbit.crypto.sphinx

import com.nesbit.crypto.*
import djb.Curve25519
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import java.security.Security
import java.util.*
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class Sphinx(
        private val random: SecureRandom = newSecureRandom(),
        val maxRouteLength: Int = 5) {
    companion object {
        private val ZERO_16 = ByteArray(16)
        private val HKDF_SALT = "SphinxHashes".toByteArray(Charsets.UTF_8)

        private val SECURITY_PARAMETER = 16 // To work with Curve25519 key (32 bytes each) and 16 bytes AES keys
        private val ENTRY_SIZE = Curve25519.KEY_SIZE + SECURITY_PARAMETER
        private val ZERO_PAD = ByteArray(ENTRY_SIZE)
        private val RHO_KEY_SIZE = SECURITY_PARAMETER * 8 // in bits
        private val GCM_KEY_SIZE = SECURITY_PARAMETER * 8 // in bits
        private val GCM_NONCE_LENGTH = 12 // in bytes
        private val GCM_TAG_LENGTH = SECURITY_PARAMETER // in bytes
        private val BLIND_LENGTH = Curve25519.KEY_SIZE // in bytes
    }

    private val rhoLength = (maxRouteLength + 1) * ENTRY_SIZE
    val betaLength = maxRouteLength * ENTRY_SIZE
    private val alphaCache = mutableSetOf<ComparableByteArray>()

    init {
        require(Curve25519.KEY_SIZE == 2 * SECURITY_PARAMETER) // Ensure sizes align properly
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun resetAlphaCache() = alphaCache.clear()

    private fun rho(rhoKey: ByteArray): ByteArray {
        val streamOutput = ByteArray(rhoLength)
        val secretKey = SecretKeySpec(rhoKey, "AES")
        val aesCipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE")
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(ZERO_16))
        return aesCipher.doFinal(streamOutput)
    }

    private fun encryptPayload(key: ByteArray, nonce: ByteArray, header: ByteArray, payload: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec)
        cipher.updateAAD(header)
        val cipherText = cipher.doFinal(payload)
        val tag = cipherText.copyOfRange(payload.size, payload.size + GCM_TAG_LENGTH)
        val newPayload = cipherText.copyOf(payload.size)
        return Pair(newPayload, tag)
    }

    private fun decryptPayload(key: ByteArray, nonce: ByteArray, header: ByteArray, tag: ByteArray, payload: ByteArray): Pair<Boolean, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce)
        val secretKey = SecretKeySpec(key, "AES")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        cipher.updateAAD(header)
        val cipherText = concatByteArrays(payload, tag)
        val decrypted = try {
            cipher.doFinal(cipherText)
        } catch (ex: AEADBadTagException) {
            return Pair(false, ByteArray(0))
        }
        return Pair(true, decrypted)
    }

    class DerivedHashes(publicKey: Curve25519PublicKey, sharedSecret: Curve25519PublicKey) {
        companion object {
            val TOTAL_KEY_BYTES = (RHO_KEY_SIZE / 8) + GCM_NONCE_LENGTH + (GCM_KEY_SIZE / 8) + BLIND_LENGTH
        }

        val rhoKey: ByteArray
        val gcmNonce: ByteArray
        val gcmKey: ByteArray
        val blind: Curve25519PrivateKey

        init {
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            hkdf.init(HKDFParameters(sharedSecret.keyBytes, HKDF_SALT, publicKey.keyBytes))
            val hkdfKey = ByteArray(TOTAL_KEY_BYTES)
            hkdf.generateBytes(hkdfKey, 0, TOTAL_KEY_BYTES)
            var start = 0
            var end = (RHO_KEY_SIZE / 8)
            rhoKey = hkdfKey.copyOfRange(start, end)
            start = end
            end += GCM_NONCE_LENGTH
            gcmNonce = hkdfKey.copyOfRange(start, end)
            start = end
            end += (GCM_KEY_SIZE / 8)
            gcmKey = hkdfKey.copyOfRange(start, end)
            start = end
            end += BLIND_LENGTH
            blind = Curve25519PrivateKey(hkdfKey.copyOfRange(start, end))
        }
    }

    data class HeaderEntry(val nextNode: Curve25519PublicKey,
                           val alpha: Curve25519PublicKey,
                           val sharedSecret: Curve25519PublicKey,
                           val hashes: DerivedHashes)

    fun createRoute(route: List<Curve25519PublicKey>, random: SecureRandom = this.random): List<HeaderEntry> {
        require(route.isNotEmpty()) { "Routing list cannot be empty" }
        val startingPoint = Curve25519KeyPair.generateKeyPair(random)
        val output = mutableListOf<HeaderEntry>()
        val firstNode = route.first()
        val firstSecret = generateSharedECDHSecret(firstNode, startingPoint.privateKey)
        val nextNode = if (route.size == 1) route[0] else route[1]
        output += HeaderEntry(nextNode, startingPoint.publicKey, firstSecret, DerivedHashes(firstNode, firstSecret))
        for (i in 1 until route.size) {
            val alpha = generateSharedECDHSecret(output[i - 1].alpha, output[i - 1].hashes.blind)
            var sharedSecret = generateSharedECDHSecret(route[i], startingPoint.privateKey)
            for (j in 0 until i) {
                sharedSecret = generateSharedECDHSecret(sharedSecret, output[j].hashes.blind)
            }
            val nextHopNode = if (i < route.size - 1) route[i + 1] else route[i]
            output += HeaderEntry(nextHopNode, alpha, sharedSecret, DerivedHashes(route[i], sharedSecret))
        }
        return output
    }

    class UnpackedSphinxMessage(betaLength: Int,
                                val header: ByteArray,
                                val payload: ByteArray,
                                val tag: ByteArray) {
        constructor(betaLength: Int, messageBytes: ByteArray) : this(
                betaLength,
                messageBytes.copyOfRange(0, Curve25519.KEY_SIZE + betaLength),
                messageBytes.copyOfRange(Curve25519.KEY_SIZE + betaLength, messageBytes.size - GCM_TAG_LENGTH),
                messageBytes.copyOfRange(messageBytes.size - GCM_TAG_LENGTH, messageBytes.size))

        init {
            require(header.size == Curve25519.KEY_SIZE + betaLength)
            require(tag.size == GCM_TAG_LENGTH)
        }

        override fun toString(): String = "header: ${header.printHex()}\npayload: ${payload.printHex()}\ntag: ${tag.printHex()}"

        val messageBytes: ByteArray get() = concatByteArrays(header, payload, tag)
    }

    fun makeMessage(route: List<Curve25519PublicKey>, payload: ByteArray, random: SecureRandom = this.random): UnpackedSphinxMessage {
        require(route.size in 1..(maxRouteLength - 1)) { "Invalid route length" }
        val headerInfo = createRoute(route, random)
        val rhoList = headerInfo.map { rho(it.hashes.rhoKey) }
        var filler = ByteArray(0)
        for (i in 0 until route.size) {
            val rhoTail = rhoList[i].copyOfRange(rhoLength - (i + 1) * ENTRY_SIZE, rhoLength)
            filler = xorByteArrays(concatByteArrays(filler, ZERO_PAD), rhoTail)
        }
        var lastBeta = filler
        var lastTag = ByteArray(GCM_TAG_LENGTH + ((maxRouteLength - route.size) * ENTRY_SIZE))
        random.nextBytes(lastTag)
        var workingPayload = payload.copyOf()
        var header = ByteArray(0)
        for (i in route.size - 1 downTo 0) {
            val info = headerInfo[i]
            val decryptedBeta = concatByteArrays(info.nextNode.keyBytes, lastTag, lastBeta)
            lastBeta = xorByteArrays(decryptedBeta, rhoList[i]).copyOf(betaLength)
            header = concatByteArrays(info.alpha.keyBytes, lastBeta)
            val enc = encryptPayload(info.hashes.gcmKey, info.hashes.gcmNonce, header, workingPayload)
            workingPayload = enc.first
            lastTag = enc.second
        }
        return UnpackedSphinxMessage(betaLength, header, workingPayload, lastTag)
    }

    fun processMessage(msg: UnpackedSphinxMessage, nodeKeys: Curve25519KeyPair): Pair<UnpackedSphinxMessage?, ByteArray?> {
        val alpha = Curve25519PublicKey(msg.header.copyOfRange(0, Curve25519.KEY_SIZE))
        val comparableAlpha = ComparableByteArray(alpha.keyBytes)
        if (comparableAlpha in alphaCache) {
            return Pair(null, null) // Never allow reuse of Diffie-Hellman points
        }
        alphaCache += comparableAlpha
        val sharedSecret = generateSharedECDHSecret(alpha, nodeKeys.privateKey)
        val hashes = DerivedHashes(nodeKeys.publicKey, sharedSecret)
        val (ok, decryptedPayload) = decryptPayload(hashes.gcmKey, hashes.gcmNonce, msg.header, msg.tag, msg.payload)
        if (!ok) {
            return Pair(null, null) // Discard bad packets
        }
        val beta = msg.header.copyOfRange(Curve25519.KEY_SIZE, msg.header.size)
        val rho = rho(hashes.rhoKey)
        val decryptedBeta = xorByteArrays(concatByteArrays(beta, ZERO_PAD), rho)
        val nextNode = decryptedBeta.copyOf(Curve25519.KEY_SIZE)
        if (Arrays.equals(nextNode, nodeKeys.publicKey.keyBytes)) {
            return Pair(null, decryptedPayload)
        }
        val nextAlpha = generateSharedECDHSecret(alpha, hashes.blind)
        val nextBeta = decryptedBeta.copyOfRange(ENTRY_SIZE, decryptedBeta.size)
        val nextTag = decryptedBeta.copyOfRange(Curve25519.KEY_SIZE, Curve25519.KEY_SIZE + GCM_TAG_LENGTH)
        return Pair(UnpackedSphinxMessage(betaLength, concatByteArrays(nextAlpha.keyBytes, nextBeta), decryptedPayload, nextTag), null)
    }
}