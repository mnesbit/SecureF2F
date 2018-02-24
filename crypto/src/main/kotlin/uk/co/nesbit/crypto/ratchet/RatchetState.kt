package uk.co.nesbit.crypto.ratchet

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES
import uk.co.nesbit.crypto.ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES
import uk.co.nesbit.crypto.ratchet.RatchetState.Companion.MessageKey.Companion.MESSAGE_KEY_SIZE
import uk.co.nesbit.crypto.session.InitiatorSessionParams
import uk.co.nesbit.crypto.session.ResponderSessionParams
import uk.co.nesbit.crypto.session.SessionSecretState
import java.io.IOException
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*
import javax.crypto.AEADBadTagException

// Based upon header encrypted Axolotl Ratchet/Double ratchet protocol
// as described in https://signal.org/docs/specifications/doubleratchet/
class RatchetState private constructor(private var senderDHKeyPair: KeyPair,
                                       private var receiverDHKey: PublicKey,
                                       private var rootKey: ByteArray,
                                       private var senderChainKey: ByteArray,
                                       private var senderHeaderKey: MessageKey,
                                       private var senderNextHeaderKey: MessageKey,
                                       private var senderSequenceNumber: Int,
                                       private var receiverChainKey: ByteArray,
                                       private var receiverHeaderKey: MessageKey,
                                       private var receiverNextHeaderKey: MessageKey,
                                       private var receiverSequenceNumber: Int,
                                       private var previousSenderChainNumber: Int,
                                       val maxSkip: Int,
                                       val maxLost: Int,
                                       private val secureRandom: SecureRandom) {
    private val skippedMessageKeys = mutableMapOf<HeaderKey, MessageKey>()

    companion object {
        private const val DEFAULT_MAX_SKIP = 3
        private const val DEFAULT_MAX_LOST = 10
        private const val CHAIN_KEY_SIZE = 32
        private val emptyKey = ByteArray(CHACHA_KEY_SIZE_BYTES)
        private val emptyIv = ByteArray(CHACHA_NONCE_SIZE_BYTES)
        private val INITIAL_SECRET_CONTEXT = "Starting Secrets".toByteArray(Charsets.UTF_8)
        private val ROOT_CHAIN_CONTEXT = "Root Key Chaining".toByteArray(Charsets.UTF_8)
        private val CHAIN_KEY_CONST1 = ByteArray(1, { 0x42 })
        private val CHAIN_KEY_CONST2 = ByteArray(1, { 0x69 })
        private val CHAIN_KEY_CONST3 = "Pootle".toByteArray(Charsets.UTF_8)

        private fun sharedKeysFromStartingSecret(startingSessionSecret: ByteArray, bobDHKey: PublicKey): Triple<ByteArray, MessageKey, MessageKey> {
            val hkdf = HKDFBytesGenerator(SHA256Digest())

            hkdf.init(HKDFParameters(startingSessionSecret, INITIAL_SECRET_CONTEXT, bobDHKey.encoded))
            val hkdfKey = ByteArray(CHAIN_KEY_SIZE + 2 * MESSAGE_KEY_SIZE)
            hkdf.generateBytes(hkdfKey, 0, hkdfKey.size)
            val splits = hkdfKey.splitByteArrays(CHAIN_KEY_SIZE, MESSAGE_KEY_SIZE, MESSAGE_KEY_SIZE)
            val rootKey = splits[0]
            val headerKey = MessageKey(splits[1])
            val nextHeaderKey = MessageKey(splits[2])
            return Triple(rootKey, headerKey, nextHeaderKey)
        }

        private class MessageKey(val key: ByteArray, val iv: ByteArray) {
            companion object {
                const val MESSAGE_KEY_SIZE = CHACHA_KEY_SIZE_BYTES + CHACHA_NONCE_SIZE_BYTES
            }

            constructor(combined: ByteArray) : this(combined.copyOf(CHACHA_KEY_SIZE_BYTES), combined.copyOfRange(CHACHA_KEY_SIZE_BYTES, CHACHA_KEY_SIZE_BYTES + CHACHA_NONCE_SIZE_BYTES))
        }

        private class RootKeyUpdate(val newRootKey: ByteArray, val chainKeyInput: ByteArray, val nextHeaderKey: MessageKey) {
            operator fun component1(): ByteArray = newRootKey
            operator fun component2(): ByteArray = chainKeyInput
            operator fun component3(): MessageKey = nextHeaderKey
        }

        private fun kdfRootKeys(rootKey: ByteArray, sessionDHOutput: ByteArray): RootKeyUpdate {
            val hkdf = HKDFBytesGenerator(SHA256Digest())
            hkdf.init(HKDFParameters(rootKey, ROOT_CHAIN_CONTEXT, sessionDHOutput))
            val hkdfKey = ByteArray(2 * CHAIN_KEY_SIZE + MESSAGE_KEY_SIZE)
            hkdf.generateBytes(hkdfKey, 0, hkdfKey.size)
            val splits = hkdfKey.splitByteArrays(CHAIN_KEY_SIZE, CHAIN_KEY_SIZE, MESSAGE_KEY_SIZE)
            val newRootKey = splits[0]
            val chainKey = splits[1]
            val nextHeaderKey = MessageKey(splits[2])
            return RootKeyUpdate(newRootKey, chainKey, nextHeaderKey)
        }

        private class ChainKeyUpdate(val newChainKey: ByteArray, val messageKey: ByteArray, val iv: ByteArray)

        private fun kdfChainKey(chainKey: ByteArray): ChainKeyUpdate {
            val newChainKey = getHMAC(chainKey, CHAIN_KEY_CONST1)
            val messageKey = getHMAC(chainKey, CHAIN_KEY_CONST2)
            val iv = getHMAC(chainKey, CHAIN_KEY_CONST3)
            return ChainKeyUpdate(newChainKey.bytes, messageKey.bytes, iv.bytes.copyOf(CHACHA_NONCE_SIZE_BYTES))
        }

        fun ratchetInitAlice(startingSessionSecret: ByteArray,
                             bobDHKey: PublicKey,
                             secureRandom: SecureRandom = newSecureRandom(),
                             maxSkip: Int = DEFAULT_MAX_SKIP,
                             maxLost: Int = DEFAULT_MAX_LOST): RatchetState {
            val aliceDHKeyPair = generateCurve25519DHKeyPair(secureRandom)
            val (startingKey, sharedHeaderKeyA, sharedNextHeaderKeyB) = sharedKeysFromStartingSecret(startingSessionSecret, bobDHKey)
            val sessionSharedDHSecret = getSharedDHSecret(aliceDHKeyPair, bobDHKey)
            val (rootKey, chainKey, senderNextHeaderKey) = kdfRootKeys(startingKey, sessionSharedDHSecret)
            return RatchetState(senderDHKeyPair = aliceDHKeyPair,
                    receiverDHKey = bobDHKey,
                    rootKey = rootKey,
                    senderChainKey = chainKey,
                    senderHeaderKey = sharedHeaderKeyA,
                    senderNextHeaderKey = senderNextHeaderKey,
                    senderSequenceNumber = 0,
                    receiverChainKey = emptyKey,
                    receiverHeaderKey = MessageKey(emptyKey, emptyIv),
                    receiverNextHeaderKey = sharedNextHeaderKeyB,
                    receiverSequenceNumber = 0,
                    previousSenderChainNumber = 0,
                    maxSkip = maxSkip,
                    maxLost = maxLost,
                    secureRandom = secureRandom)
        }

        fun ratchetInitBob(startingSessionSecret: ByteArray,
                           bobDHKeyPair: KeyPair,
                           secureRandom: SecureRandom = newSecureRandom(),
                           maxSkip: Int = DEFAULT_MAX_SKIP,
                           maxLost: Int = DEFAULT_MAX_LOST): RatchetState {
            val (startingKey, sharedHeaderKeyA, sharedNextHeaderKeyB) = sharedKeysFromStartingSecret(startingSessionSecret, bobDHKeyPair.public)
            return RatchetState(senderDHKeyPair = bobDHKeyPair,
                    receiverDHKey = Curve25519PublicKey(emptyKey),
                    rootKey = startingKey,
                    senderChainKey = emptyKey,
                    senderHeaderKey = MessageKey(emptyKey, emptyIv),
                    senderNextHeaderKey = sharedNextHeaderKeyB,
                    senderSequenceNumber = 0,
                    receiverChainKey = emptyKey,
                    receiverHeaderKey = MessageKey(emptyKey, emptyIv),
                    receiverNextHeaderKey = sharedHeaderKeyA,
                    receiverSequenceNumber = 0,
                    previousSenderChainNumber = 0,
                    maxSkip = maxSkip,
                    maxLost = maxLost,
                    secureRandom = secureRandom)
        }

        fun ratchetInitForSession(initiatorInit: InitiatorSessionParams,
                                  responderInit: ResponderSessionParams,
                                  dhKeys: KeyPair,
                                  secureRandom: SecureRandom = newSecureRandom(),
                                  maxSkip: Int = DEFAULT_MAX_SKIP,
                                  maxLost: Int = DEFAULT_MAX_LOST): RatchetState {
            val sharedSecretState = SessionSecretState(initiatorInit, responderInit, dhKeys)
            return if (dhKeys.public == initiatorInit.initiatorDHPublicKey) {
                ratchetInitAlice(sharedSecretState.sessionRootKey, responderInit.responderDHPublicKey, secureRandom, maxSkip, maxLost)
            } else {
                ratchetInitBob(sharedSecretState.sessionRootKey, dhKeys, secureRandom, maxSkip, maxLost)
            }
        }
    }

    private class HeaderKey(val key: ByteArray, val iv: ByteArray, val sequenceNumber: Int) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as HeaderKey

            if (!Arrays.equals(key, other.key)) return false
            if (!Arrays.equals(iv, other.iv)) return false
            if (sequenceNumber != other.sequenceNumber) return false

            return true
        }

        override fun hashCode(): Int {
            var result = Arrays.hashCode(key)
            result = 31 * result + Arrays.hashCode(iv)
            result = 31 * result + sequenceNumber
            return result
        }
    }

    private fun headerEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray): ByteArray {
        val encrypter = ChaCha20Poly1305.Encode(ParametersWithIV(KeyParameter(key), iv))
        return encrypter.encodeCiphertext(plaintext, null)
    }

    private fun headerDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray {
        val encrypter = ChaCha20Poly1305.Decode(ParametersWithIV(KeyParameter(key), iv))
        return encrypter.decodeCiphertext(ciphertext, null)
    }

    private fun meassageAadEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val encrypter = ChaCha20Poly1305.Encode(ParametersWithIV(KeyParameter(key), iv))
        return encrypter.encodeCiphertext(plaintext, aad)
    }

    private fun meassageAadDecrypt(key: ByteArray, iv: ByteArray, ciphertext: ByteArray, aad: ByteArray? = null): ByteArray {
        val encrypter = ChaCha20Poly1305.Decode(ParametersWithIV(KeyParameter(key), iv))
        return encrypter.decodeCiphertext(ciphertext, aad)
    }

    fun encryptMessage(plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val chainUpdate = kdfChainKey(senderChainKey)
        senderChainKey = chainUpdate.newChainKey
        val header = RatchetHeader(senderDHKeyPair.public, previousSenderChainNumber, senderSequenceNumber)
        val encryptedHeader = headerEncrypt(senderHeaderKey.key, senderHeaderKey.iv, header.serialize())
        ++senderSequenceNumber
        val mergedAad = if (aad == null) encryptedHeader else concatByteArrays(encryptedHeader, aad)
        val encryptedPayload = meassageAadEncrypt(chainUpdate.messageKey, chainUpdate.iv, plaintext, mergedAad)
        val ratchetMessage = RatchetMessage(encryptedHeader, encryptedPayload)
        return ratchetMessage.serialize()
    }

    private fun tryDecryptWithSkippedKeys(ratchetMessage: RatchetMessage, aad: ByteArray?): ByteArray? {
        for ((headerKey, messageKey) in skippedMessageKeys) {
            try {
                val decryptedHeaderBytes = headerDecrypt(headerKey.key, headerKey.iv, ratchetMessage.encryptedHeader)
                val decryptedHeader = try {
                    RatchetHeader.deserialize(decryptedHeaderBytes)
                } catch (ex: IOException) {
                    continue
                }
                val reserialized = decryptedHeader.serialize()
                if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(decryptedHeaderBytes, reserialized)) {
                    throw AEADBadTagException()
                }
                if (decryptedHeader.sequenceNumber == headerKey.sequenceNumber) {
                    skippedMessageKeys.remove(headerKey)
                    val mergedAad = if (aad == null) ratchetMessage.encryptedHeader else concatByteArrays(ratchetMessage.encryptedHeader, aad)
                    return meassageAadDecrypt(messageKey.key, messageKey.iv, ratchetMessage.encryptedPayload, mergedAad)
                }
            } catch (ex: AEADBadTagException) {
                // Ignore
            }
        }
        return null
    }

    private fun skipMessageKeys(until: Int) {
        if (receiverSequenceNumber + maxSkip < until) {
            throw RatchetException()
        }
        if ((skippedMessageKeys.size + (until - receiverSequenceNumber)) > maxLost) {
            throw RatchetException()
        }
        if (!Arrays.equals(receiverChainKey, emptyKey)) {
            while (receiverSequenceNumber < until) {
                val chainUpdate = kdfChainKey(receiverChainKey)
                receiverChainKey = chainUpdate.newChainKey
                val headerKey = HeaderKey(receiverHeaderKey.key, receiverHeaderKey.iv, receiverSequenceNumber)
                val messageKey = MessageKey(chainUpdate.messageKey, chainUpdate.iv)
                skippedMessageKeys[headerKey] = messageKey
                ++receiverSequenceNumber
            }
        }
    }

    private fun ratchetStep(ratchetHeader: RatchetHeader) {
        previousSenderChainNumber = senderSequenceNumber
        senderSequenceNumber = 0
        receiverSequenceNumber = 0
        senderHeaderKey = senderNextHeaderKey
        receiverHeaderKey = receiverNextHeaderKey
        receiverDHKey = ratchetHeader.senderDHKey
        val receiverUpdate = kdfRootKeys(rootKey, getSharedDHSecret(senderDHKeyPair, receiverDHKey))
        rootKey = receiverUpdate.newRootKey
        receiverChainKey = receiverUpdate.chainKeyInput
        receiverNextHeaderKey = receiverUpdate.nextHeaderKey
        senderDHKeyPair = generateCurve25519DHKeyPair(secureRandom)
        val senderUpdate = kdfRootKeys(rootKey, getSharedDHSecret(senderDHKeyPair, receiverDHKey))
        rootKey = senderUpdate.newRootKey
        senderChainKey = senderUpdate.chainKeyInput
        senderNextHeaderKey = senderUpdate.nextHeaderKey
    }

    data class HeaderDecryptResult(val decryptedHeader: RatchetHeader, val doRatchetStep: Boolean)

    private fun decryptHeader(encryptedHeader: ByteArray): HeaderDecryptResult {
        try {
            val decryptedHeaderBytes = headerDecrypt(receiverNextHeaderKey.key, receiverNextHeaderKey.iv, encryptedHeader)
            val decryptedHeader = try {
                RatchetHeader.deserialize(decryptedHeaderBytes)
            } catch (ex: IOException) {
                throw AEADBadTagException()
            }
            val reserialized = decryptedHeader.serialize()
            if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(decryptedHeaderBytes, reserialized)) {
                throw AEADBadTagException()
            }
            return HeaderDecryptResult(decryptedHeader, true)
        } catch (ex: AEADBadTagException) {
            // Ignore
        }
        try {
            val decryptedHeaderBytes = headerDecrypt(receiverHeaderKey.key, receiverHeaderKey.iv, encryptedHeader)
            val decryptedHeader = try {
                RatchetHeader.deserialize(decryptedHeaderBytes)
            } catch (ex: IOException) {
                throw AEADBadTagException()
            }
            val reserialized = decryptedHeader.serialize()
            if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(decryptedHeaderBytes, reserialized)) {
                throw AEADBadTagException()
            }
            return HeaderDecryptResult(decryptedHeader, false)
        } catch (ex: AEADBadTagException) {
            // Ignore
        }
        throw RatchetException()
    }

    fun decryptMessage(encrypted: ByteArray, aad: ByteArray? = null): ByteArray {
        val ratchetMessage = try {
            RatchetMessage.deserialize(encrypted)
        } catch (ex: IOException) {
            throw RatchetException()
        }
        val reserialized = ratchetMessage.serialize()
        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(encrypted, reserialized)) {
            throw RatchetException()
        }
        val plaintext = tryDecryptWithSkippedKeys(ratchetMessage, aad)
        if (plaintext != null) {
            return plaintext
        }
        val (decryptedHeader, doRatchetStep) = decryptHeader(ratchetMessage.encryptedHeader)
        if (doRatchetStep) {
            skipMessageKeys(decryptedHeader.previousChainCount)
            ratchetStep(decryptedHeader)
        }
        skipMessageKeys(decryptedHeader.sequenceNumber)
        val chainUpdate = kdfChainKey(receiverChainKey)
        val mergedAad = if (aad == null) ratchetMessage.encryptedHeader else concatByteArrays(ratchetMessage.encryptedHeader, aad)
        val decrypted = try {
            meassageAadDecrypt(chainUpdate.messageKey, chainUpdate.iv, ratchetMessage.encryptedPayload, mergedAad)
        } catch (ex: AEADBadTagException) {
            throw RatchetException()
        }
        receiverChainKey = chainUpdate.newChainKey
        ++receiverSequenceNumber
        return decrypted
    }
}