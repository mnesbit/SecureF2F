package uk.co.nesbit.crypto.sphinx

import djb.Curve25519
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import uk.co.nesbit.crypto.*
import uk.co.nesbit.utils.printHexBinary
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class Sphinx(
        private val random: SecureRandom = newSecureRandom(),
        val maxRouteLength: Int = 5,
        val payloadRoundingSize: Int = 1024) {
    companion object {
        private val ZERO_16 = ByteArray(16)
        private val HKDF_SALT = "SphinxHashes".toByteArray(Charsets.UTF_8)

        private const val SECURITY_PARAMETER = 16 // To work with Curve25519 key (32 bytes each) and 16 bytes AES keys
        private const val ID_HASH_SIZE = 2 * SECURITY_PARAMETER // Use SHA-256 of signing key and Curve25519 key
        private const val RHO_KEY_SIZE = SECURITY_PARAMETER * 8 // in bytes
        private const val GCM_KEY_SIZE = SECURITY_PARAMETER * 8 // in bytes
        private const val GCM_NONCE_LENGTH = 12 // in bytes
        private const val GCM_TAG_LENGTH = SECURITY_PARAMETER // in bytes
        private const val BLIND_LENGTH = Curve25519.KEY_SIZE // in bytes
        private const val ENTRY_SIZE = ID_HASH_SIZE + GCM_TAG_LENGTH
        private val ZERO_PAD = ByteArray(ENTRY_SIZE)
    }

    private val rhoLength = (maxRouteLength + 1) * ENTRY_SIZE
    internal val betaLength = maxRouteLength * ENTRY_SIZE
    private val alphaCache = mutableSetOf<SecureHash>()

    init {
        require(Curve25519.KEY_SIZE == 2 * SECURITY_PARAMETER) // Ensure sizes align properly
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    fun resetAlphaCache() = alphaCache.clear()

    private fun rho(rhoKey: SecretKeySpec): ByteArray {
        val streamOutput = ByteArray(rhoLength)
        val aesCipher = Cipher.getInstance("AES/CTR/NoPadding", "SunJCE")
        aesCipher.init(Cipher.ENCRYPT_MODE, rhoKey, IvParameterSpec(ZERO_16))
        return aesCipher.doFinal(streamOutput)
    }

    private class EncryptionResult(val newPayload: ByteArray, val tag: ByteArray)

    private fun encryptPayload(key: SecretKeySpec, nonce: ByteArray, header: ByteArray, payload: ByteArray): EncryptionResult {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, spec)
        cipher.updateAAD(header)
        val cipherText = cipher.doFinal(payload)
        val tag = cipherText.copyOfRange(payload.size, payload.size + GCM_TAG_LENGTH)
        val newPayload = cipherText.copyOf(payload.size)
        return EncryptionResult(newPayload, tag)
    }

    private class DecryptionResult(val valid: Boolean, val newPayload: ByteArray)

    private fun decryptPayload(key: SecretKeySpec, nonce: ByteArray, header: ByteArray, tag: ByteArray, payload: ByteArray): DecryptionResult {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        cipher.updateAAD(header)
        val cipherText = concatByteArrays(payload, tag)
        val decrypted = try {
            cipher.doFinal(cipherText)
        } catch (ex: AEADBadTagException) {
            return DecryptionResult(false, ByteArray(0))
        }
        return DecryptionResult(true, decrypted)
    }

    private fun padSourcePayload(input: ByteArray, secureRandom: SecureRandom): ByteArray {
        val length = input.size
        val paddingSize = payloadRoundingSize - (length + 4).rem(payloadRoundingSize)
        val paddedSize = length + 4 + paddingSize
        val paddedPayload = ByteArray(paddedSize)
        secureRandom.nextBytes(paddedPayload)
        val buf = ByteBuffer.wrap(paddedPayload)
        buf.putInt(length)
        buf.put(input)
        return paddedPayload
    }

    private fun unpadFinalPayload(input: ByteArray): ByteArray {
        val buf = ByteBuffer.wrap(input)
        val length = buf.getInt()
        val output = ByteArray(length)
        buf.get(output, 0, length)
        return output
    }

    internal class DerivedHashes(context: SecureHash, sharedSecret: PublicKey) {
        companion object {
            private const val TOTAL_KEY_BYTES = (RHO_KEY_SIZE / 8) + GCM_NONCE_LENGTH + (GCM_KEY_SIZE / 8) + BLIND_LENGTH
        }

        val rhoKey: SecretKeySpec
        val gcmNonce: ByteArray
        val gcmKey: SecretKeySpec
        val blind: PrivateKey

        init {
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            hkdf.init(HKDFParameters(sharedSecret.encoded, HKDF_SALT, context.bytes))
            val hkdfKey = ByteArray(TOTAL_KEY_BYTES)
            hkdf.generateBytes(hkdfKey, 0, hkdfKey.size)
            val splits = hkdfKey.splitByteArrays((RHO_KEY_SIZE / 8), GCM_NONCE_LENGTH, (GCM_KEY_SIZE / 8), BLIND_LENGTH)
            rhoKey = SecretKeySpec(splits[0], "AES")
            gcmNonce = splits[1]
            gcmKey = SecretKeySpec(splits[2], "AES")
            blind = Curve25519PrivateKey(splits[3])
        }
    }

    internal class HeaderEntry(val nextNodeId: SecureHash,
                               val alpha: PublicKey,
                               val sharedSecret: PublicKey,
                               val hashes: DerivedHashes) {
        init {
            require(nextNodeId.bytes.size == ID_HASH_SIZE)
        }
    }

    internal fun createRoute(route: List<SphinxPublicIdentity>, random: SecureRandom = this.random): List<HeaderEntry> {
        require(route.size in 1..maxRouteLength) { "Invalid route length" }
        val startingPoint = generateCurve25519DHKeyPair(random)
        val output = mutableListOf<HeaderEntry>()
        val firstNode = route.first()
        val firstSecret = Curve25519PublicKey(getSharedDHSecret(startingPoint, firstNode.diffieHellmanPublicKey))
        val nextNode = if (route.size == 1) route[0] else route[1]
        output += HeaderEntry(nextNode.id, startingPoint.public, firstSecret, DerivedHashes(firstNode.id, firstSecret))
        for (i in 1 until route.size) {
            val alpha = Curve25519PublicKey(getSharedDHSecret(output[i - 1].hashes.blind, output[i - 1].alpha))
            var sharedSecret = Curve25519PublicKey(getSharedDHSecret(startingPoint.private, route[i].diffieHellmanPublicKey))
            for (j in 0 until i) {
                sharedSecret = Curve25519PublicKey(getSharedDHSecret(output[j].hashes.blind, sharedSecret))
            }
            val nextHopNode = if (i < route.size - 1) route[i + 1] else route[i]
            output += HeaderEntry(nextHopNode.id, alpha, sharedSecret, DerivedHashes(route[i].id, sharedSecret))
        }
        return output
    }

    class UnpackedSphinxMessage(betaLength: Int,
                                val header: ByteArray,
                                val payload: ByteArray,
                                val tag: ByteArray) {
        constructor(betaLength: Int, messageBytes: ByteArray) : this(
                betaLength,
                messageBytes.copyOfRange(0, ID_HASH_SIZE + betaLength),
                messageBytes.copyOfRange(ID_HASH_SIZE + betaLength, messageBytes.size - GCM_TAG_LENGTH),
                messageBytes.copyOfRange(messageBytes.size - GCM_TAG_LENGTH, messageBytes.size))

        init {
            require(header.size == ID_HASH_SIZE + betaLength)
            require(tag.size == GCM_TAG_LENGTH)
        }

        override fun toString(): String = "header: ${header.printHexBinary()}\npayload: ${payload.printHexBinary()}\ntag: ${tag.printHexBinary()}"

        val messageBytes: ByteArray get() = concatByteArrays(header, payload, tag)
    }

    fun makeMessage(route: List<SphinxPublicIdentity>, payload: ByteArray, random: SecureRandom = this.random): UnpackedSphinxMessage {
        require(route.size in 1..maxRouteLength) { "Invalid route length" }
        require(route.all { it.id.bytes.size == ID_HASH_SIZE }) { "ID Hash wrong size length" }// Ensure sizes align properly
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
        var workingPayload = padSourcePayload(payload, random)
        var header = ByteArray(0)
        for (i in route.size - 1 downTo 0) {
            val info = headerInfo[i]
            val decryptedBeta = concatByteArrays(info.nextNodeId.bytes, lastTag, lastBeta)
            lastBeta = xorByteArrays(decryptedBeta, rhoList[i]).copyOf(betaLength)
            header = concatByteArrays(info.alpha.encoded, lastBeta)
            val enc = encryptPayload(info.hashes.gcmKey, info.hashes.gcmNonce, header, workingPayload)
            workingPayload = enc.newPayload
            lastTag = enc.tag
        }
        return UnpackedSphinxMessage(betaLength, header, workingPayload, lastTag)
    }

    class MessageProcessingResult(val valid: Boolean,
                                  val forwardMessage: UnpackedSphinxMessage?,
                                  val nextNode: SecureHash?,
                                  val finalPayload: ByteArray?)

    fun processMessage(msg: UnpackedSphinxMessage, nodeKeys: SphinxIdentityKeyPair): MessageProcessingResult {
        val nodeId = nodeKeys.id
        val dhFunction = { x: PublicKey -> getSharedDHSecret(nodeKeys.diffieHellmanKeys, x) }
        return processMessage(msg, nodeId, dhFunction)
    }

    fun processMessage(msg: ByteArray, nodeId: SecureHash, dhFunction: (remotePublicKey: PublicKey) -> ByteArray): MessageProcessingResult {
        if ((msg.size < ID_HASH_SIZE + betaLength + GCM_TAG_LENGTH)
                || ((msg.size - ID_HASH_SIZE - betaLength - GCM_TAG_LENGTH).rem(payloadRoundingSize) != 0)) {
            return MessageProcessingResult(false, null, null, null)
        }
        val unpacked = UnpackedSphinxMessage(betaLength, msg)
        return processMessage(unpacked, nodeId, dhFunction)
    }

    fun processMessage(msg: UnpackedSphinxMessage, nodeId: SecureHash, dhFunction: (remotePublicKey: PublicKey) -> ByteArray): MessageProcessingResult {
        require(nodeId.bytes.size == ID_HASH_SIZE) { "ID Hash wrong size length" }// Ensure sizes align properly
        val alpha = Curve25519PublicKey(msg.header.copyOfRange(0, Curve25519.KEY_SIZE))
        val comparableAlpha = alpha.keyBytes.secureHash()
        if (comparableAlpha in alphaCache) {
            return MessageProcessingResult(false, null, null, null) // Never allow reuse of Diffie-Hellman points
        }
        alphaCache += comparableAlpha
        val sharedSecret = Curve25519PublicKey(dhFunction(alpha))
        val hashes = DerivedHashes(nodeId, sharedSecret)
        val dec = decryptPayload(hashes.gcmKey, hashes.gcmNonce, msg.header, msg.tag, msg.payload)
        if (!dec.valid) {
            return MessageProcessingResult(false, null, null, null) // Discard bad packets
        }
        val beta = msg.header.copyOfRange(Curve25519.KEY_SIZE, msg.header.size)
        val rho = rho(hashes.rhoKey)
        val decryptedBeta = xorByteArrays(concatByteArrays(beta, ZERO_PAD), rho)
        val nextNode = SecureHash(SphinxPublicIdentity.ID_HASH_ALGORITHM, decryptedBeta.copyOf(ID_HASH_SIZE))
        if (nextNode == nodeId) {
            return MessageProcessingResult(true, null, nextNode, unpadFinalPayload(dec.newPayload))
        }
        val nextAlpha = Curve25519PublicKey(getSharedDHSecret(hashes.blind, alpha))
        val nextBeta = decryptedBeta.copyOfRange(ENTRY_SIZE, decryptedBeta.size)
        val nextTag = decryptedBeta.copyOfRange(Curve25519.KEY_SIZE, Curve25519.KEY_SIZE + GCM_TAG_LENGTH)
        val forwardMessage = UnpackedSphinxMessage(betaLength, concatByteArrays(nextAlpha.keyBytes, nextBeta), dec.newPayload, nextTag)
        return MessageProcessingResult(true, forwardMessage, nextNode, null)
    }

}