package uk.co.nesbit.crypto

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.ChaCha20Poly1305.CHACHA_KEY_SIZE_BYTES
import uk.co.nesbit.crypto.ChaCha20Poly1305.CHACHA_NONCE_SIZE_BYTES
import uk.co.nesbit.crypto.GCMConstants.GCM_KEY_SIZE
import uk.co.nesbit.crypto.GCMConstants.GCM_NONCE_LENGTH
import uk.co.nesbit.crypto.GCMConstants.GCM_TAG_LENGTH
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

internal class EciesMessage(
    val ephemeralKey: PublicKey,
    val nonce: Long,
    val encryptedData: ByteArray
) : AvroConvertible {
    constructor(eciesRecord: GenericRecord) : this(
        eciesRecord.getTyped("ephemeralKey"),
        eciesRecord.getTyped("nonce"),
        eciesRecord.getTyped("encryptedData")
    )

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val eciesMessageSchema: Schema = Schema.Parser()
            .addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema))
            .parse(javaClass.enclosingClass.getResourceAsStream("eciesmessage.avsc"))

        fun deserialize(bytes: ByteArray): EciesMessage {
            val eciesRecord = eciesMessageSchema.deserialize(bytes)
            return EciesMessage(eciesRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val eciesRecord = GenericData.Record(eciesMessageSchema)
        eciesRecord.putTyped("ephemeralKey", ephemeralKey)
        eciesRecord.putTyped("nonce", nonce)
        eciesRecord.putTyped("encryptedData", encryptedData)
        return eciesRecord
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as EciesMessage

        if (ephemeralKey != other.ephemeralKey) return false
        if (nonce != other.nonce) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ephemeralKey.hashCode()
        result = 31 * result + nonce.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        return result
    }
}

object Ecies {
    private val MAGIC_CONST1 = "ECIES Magic Bits".toByteArray(Charsets.UTF_8)

    @JvmStatic
    private val counter = AtomicLong(0L)


    private fun generateKeys(
        sharedSecret: ByteArray,
        senderEphemeralPublicKey: PublicKey,
        targetPublicKey: PublicKey,
        count: Long
    ): Pair<SecretKeySpec, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(
            HKDFParameters(
                sharedSecret,
                null,
                concatByteArrays(MAGIC_CONST1, senderEphemeralPublicKey.encoded, targetPublicKey.encoded)
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
        val countBytes = count.toByteArray()
        aesNonce[0] = aesNonce[0] xor countBytes[0]
        aesNonce[1] = aesNonce[1] xor countBytes[1]
        aesNonce[2] = aesNonce[2] xor countBytes[2]
        aesNonce[3] = aesNonce[3] xor countBytes[3]
        aesNonce[4] = aesNonce[4] xor countBytes[4]
        aesNonce[5] = aesNonce[5] xor countBytes[5]
        aesNonce[6] = aesNonce[6] xor countBytes[6]
        aesNonce[7] = aesNonce[7] xor countBytes[7]
        return Pair(aesKey, aesNonce)
    }

    fun encryptMessage(
        message: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        random: SecureRandom = newSecureRandom()
    ): ByteArray {
        val ephemeralKeyPair = when (targetPublicKey.algorithm) {
            "DH" -> generateDHKeyPair(random)
            "EC" -> generateECDHKeyPair(random)
            "NACLCurve25519" -> generateNACLDHKeyPair(random)
            else -> throw AEADBadTagException("Unsupported Diffie-Hellman algorithm ${targetPublicKey.algorithm}")
        }
        val aadToEncode = concatByteArrays(
            aad
                ?: ByteArray(0), ephemeralKeyPair.public.serialize(), targetPublicKey.serialize()
        )
        val sharedSecret = getSharedDHSecret(ephemeralKeyPair, targetPublicKey)
        ephemeralKeyPair.private.safeDestroy()
        val count = counter.getAndIncrement()
        val (aesKey, aesNonce) = generateKeys(sharedSecret, ephemeralKeyPair.public, targetPublicKey, count)
        Arrays.fill(sharedSecret, 0)
        return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
            val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, aesNonce)
            init(Cipher.ENCRYPT_MODE, aesKey, spec)
            updateAAD(aadToEncode)
            val outputMessage = EciesMessage(ephemeralKeyPair.public, count, doFinal(message))
            outputMessage.serialize()
        }
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        nodeKeys: KeyPair
    ): ByteArray {
        val dhFunction = { x: PublicKey -> getSharedDHSecret(nodeKeys, x) }
        return decryptMessage(encryptedMessage, aad, nodeKeys.public, dhFunction)
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        dhFunction: (remotePublicKey: PublicKey) -> ByteArray
    ): ByteArray {
        val message = try {
            val decode = EciesMessage.deserialize(encryptedMessage)
            val reserialized = decode.serialize()
            if (!reserialized.contentEquals(encryptedMessage)) throw IllegalArgumentException("doesn't round trip")
            decode
        } catch (ex: Throwable) {
            throw AEADBadTagException("Invalid ecies message")
        }
        val aadToValidate = concatByteArrays(
            aad
                ?: ByteArray(0), message.ephemeralKey.serialize(), targetPublicKey.serialize()
        )
        val sharedSecret = try {
            dhFunction(message.ephemeralKey)
        } catch (ex: Throwable) {
            throw AEADBadTagException("Invalid keys")
        }
        val (aesKey, aesNonce) = generateKeys(sharedSecret, message.ephemeralKey, targetPublicKey, message.nonce)
        Arrays.fill(sharedSecret, 0)
        return ProviderCache.withCipherInstance("AES/GCM/NoPadding", "SunJCE") {
            val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, aesNonce)
            init(Cipher.DECRYPT_MODE, aesKey, spec)
            updateAAD(aadToValidate)
            doFinal(message.encryptedData)
        }
    }
}

object EciesChaCha {
    private val MAGIC_CONST1 = "ECIES ChaCha Magic Bits".toByteArray(Charsets.UTF_8)

    @JvmStatic
    private val counter = AtomicLong(0)

    private fun generateKeys(
        sharedSecret: ByteArray,
        senderEphemeralPublicKey: PublicKey,
        targetPublicKey: PublicKey,
        count: Long
    ): Pair<ByteArray, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(
            HKDFParameters(
                sharedSecret,
                null,
                concatByteArrays(MAGIC_CONST1, senderEphemeralPublicKey.encoded, targetPublicKey.encoded)
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
        val countBytes = count.toByteArray()
        chaChaNonce[0] = chaChaNonce[0] xor countBytes[0]
        chaChaNonce[1] = chaChaNonce[1] xor countBytes[1]
        chaChaNonce[2] = chaChaNonce[2] xor countBytes[2]
        chaChaNonce[3] = chaChaNonce[3] xor countBytes[3]
        chaChaNonce[4] = chaChaNonce[4] xor countBytes[4]
        chaChaNonce[5] = chaChaNonce[5] xor countBytes[5]
        chaChaNonce[6] = chaChaNonce[6] xor countBytes[6]
        chaChaNonce[7] = chaChaNonce[7] xor countBytes[7]
        return Pair(chaChaKey, chaChaNonce)
    }

    fun encryptMessage(
        message: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        random: SecureRandom = newSecureRandom()
    ): ByteArray {
        val ephemeralKeyPair = when (targetPublicKey.algorithm) {
            "DH" -> generateDHKeyPair(random)
            "EC" -> generateECDHKeyPair(random)
            "NACLCurve25519" -> generateNACLDHKeyPair(random)
            else -> throw AEADBadTagException("Unsupported Diffie-Hellman algorithm ${targetPublicKey.algorithm}")
        }
        val aadToEncode = concatByteArrays(
            aad ?: ByteArray(0), ephemeralKeyPair.public.serialize(), targetPublicKey.serialize()
        )
        val sharedSecret = getSharedDHSecret(ephemeralKeyPair, targetPublicKey)
        ephemeralKeyPair.private.safeDestroy()
        val count = counter.getAndIncrement()
        val (chaChaKey, chaChaNonce) = generateKeys(sharedSecret, ephemeralKeyPair.public, targetPublicKey, count)
        Arrays.fill(sharedSecret, 0)
        return EciesMessage(
            ephemeralKeyPair.public,
            count,
            chaChaEncrypt(chaChaKey, chaChaNonce, message, aadToEncode)
        ).serialize()
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        nodeKeys: KeyPair
    ): ByteArray {
        val dhFunction = { x: PublicKey -> getSharedDHSecret(nodeKeys, x) }
        return decryptMessage(encryptedMessage, aad, nodeKeys.public, dhFunction)
    }

    fun decryptMessage(
        encryptedMessage: ByteArray,
        aad: ByteArray? = null,
        targetPublicKey: PublicKey,
        dhFunction: (remotePublicKey: PublicKey) -> ByteArray
    ): ByteArray {
        val message = try {
            val decode = EciesMessage.deserialize(encryptedMessage)
            val reserialized = decode.serialize()
            if (!reserialized.contentEquals(encryptedMessage)) throw IllegalArgumentException("doesn't round trip")
            decode
        } catch (ex: Throwable) {
            throw AEADBadTagException("Invalid ecies message")
        }
        val aadToValidate = concatByteArrays(
            aad
                ?: ByteArray(0), message.ephemeralKey.serialize(), targetPublicKey.serialize()
        )
        val sharedSecret = try {
            dhFunction(message.ephemeralKey)
        } catch (ex: Throwable) {
            throw AEADBadTagException("Invalid keys")
        }
        val (chaChaKey, chaChaNonce) = generateKeys(
            sharedSecret,
            message.ephemeralKey,
            targetPublicKey,
            message.nonce
        )
        return chaChaDecrypt(chaChaKey, chaChaNonce, message.encryptedData, aadToValidate)
    }
}