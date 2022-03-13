package uk.co.nesbit.crypto

import net.i2p.crypto.eddsa.EdDSAEngine
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac

@Suppress("UNCHECKED_CAST")
object ProviderCache {
    init {
        System.setProperty("org.bouncycastle.pkcs8.v1_info_only", "true")
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    private val pools = ConcurrentHashMap<String, ConcurrentLinkedQueue<*>>()

    fun <R> withMacInstance(algorithm: String, block: Mac.() -> R): R = withMacInstance(algorithm, null, block)

    fun <R> withMacInstance(algorithm: String, provider: String?, block: Mac.() -> R): R {
        val pool =
            pools.getOrPut("MAC[$algorithm|$provider]") { ConcurrentLinkedQueue<Mac>() } as ConcurrentLinkedQueue<Mac>
        val mac = pool.poll()
            ?: if (provider != null) Mac.getInstance(algorithm, provider) else Mac.getInstance(algorithm)
        try {
            return mac.block()
        } finally {
            pool.offer(mac)
        }
    }

    fun <R> withSignatureInstance(algorithm: String, block: Signature.() -> R): R = withSignatureInstance(algorithm, null, block)

    fun <R> withSignatureInstance(algorithm: String, provider: String?, block: Signature.() -> R): R {
        val pool = pools.getOrPut("SIGNATURE[$algorithm|$provider]") { ConcurrentLinkedQueue<Signature>() } as ConcurrentLinkedQueue<Signature>
        val sig = pool.poll()
                ?: if (provider != null) Signature.getInstance(algorithm, provider) else Signature.getInstance(algorithm)
        try {
            return sig.block()
        } finally {
            pool.offer(sig)
        }
    }

    fun <R> withEdDSAEngine(block: Signature.() -> R): R {
        val pool = pools.getOrPut("EDDSA[EDDSA]") { ConcurrentLinkedQueue<Signature>() } as ConcurrentLinkedQueue<Signature>
        val sig = pool.poll() ?: EdDSAEngine()
        try {
            return sig.block()
        } finally {
            pool.offer(sig)
        }
    }

    fun <R> withKeyPairGeneratorInstance(algorithm: String, block: KeyPairGenerator.() -> R): R = withKeyPairGeneratorInstance(algorithm, null, block)

    fun <R> withKeyPairGeneratorInstance(algorithm: String, provider: String?, block: KeyPairGenerator.() -> R): R {
        val pool = pools.getOrPut("KEYPAIRGENERATOR[$algorithm|$provider]") { ConcurrentLinkedQueue<KeyPairGenerator>() } as ConcurrentLinkedQueue<KeyPairGenerator>
        val generator = pool.poll()
                ?: if (provider != null) KeyPairGenerator.getInstance(algorithm, provider) else KeyPairGenerator.getInstance(algorithm)
        try {
            return generator.block()
        } finally {
            pool.offer(generator)
        }
    }

    fun <R> withMessageDigestInstance(algorithm: String, block: MessageDigest.() -> R): R = withMessageDigestInstance(algorithm, null, block)

    fun <R> withMessageDigestInstance(algorithm: String, provider: String?, block: MessageDigest.() -> R): R {
        val pool = pools.getOrPut("MESSAGEDIGEST[$algorithm|$provider]") { ConcurrentLinkedQueue<MessageDigest>() } as ConcurrentLinkedQueue<MessageDigest>
        val digest = pool.poll()
                ?: if (provider != null) MessageDigest.getInstance(algorithm, provider) else MessageDigest.getInstance(algorithm)
        try {
            return digest.block()
        } finally {
            pool.offer(digest)
        }
    }

    fun <R> withKeyAgreementInstance(algorithm: String, block: KeyAgreement.() -> R): R = withKeyAgreementInstance(algorithm, null, block)

    fun <R> withKeyAgreementInstance(algorithm: String, provider: String?, block: KeyAgreement.() -> R): R {
        val pool = pools.getOrPut("KEYAGGREEMENT[$algorithm|$provider]") { ConcurrentLinkedQueue<KeyAgreement>() } as ConcurrentLinkedQueue<KeyAgreement>
        val agreement = pool.poll()
                ?: if (provider != null) KeyAgreement.getInstance(algorithm, provider) else KeyAgreement.getInstance(algorithm)
        try {
            return agreement.block()
        } finally {
            pool.offer(agreement)
        }
    }

    fun <R> withKeyFactoryInstance(algorithm: String, block: KeyFactory.() -> R): R = withKeyFactoryInstance(algorithm, null, block)

    fun <R> withKeyFactoryInstance(algorithm: String, provider: String?, block: KeyFactory.() -> R): R {
        val pool = pools.getOrPut("KEYFACTORY[$algorithm|$provider]") { ConcurrentLinkedQueue<KeyFactory>() } as ConcurrentLinkedQueue<KeyFactory>
        val factory = pool.poll()
                ?: if (provider != null) KeyFactory.getInstance(algorithm, provider) else KeyFactory.getInstance(algorithm)
        try {
            return factory.block()
        } finally {
            pool.offer(factory)
        }
    }

    fun <R> withCipherInstance(algorithm: String, block: Cipher.() -> R): R = withCipherInstance(algorithm, null, block)

    fun <R> withCipherInstance(algorithm: String, provider: String?, block: Cipher.() -> R): R {
        val pool = pools.getOrPut("CIPHER[$algorithm|$provider]") { ConcurrentLinkedQueue<Cipher>() } as ConcurrentLinkedQueue<Cipher>
        val cipher = pool.poll()
                ?: if (provider != null) Cipher.getInstance(algorithm, provider) else Cipher.getInstance(algorithm)
        try {
            return cipher.block()
        } finally {
            pool.offer(cipher)
        }
    }

}