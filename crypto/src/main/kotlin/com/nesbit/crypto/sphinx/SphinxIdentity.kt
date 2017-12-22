package com.nesbit.crypto.sphinx

import com.nesbit.crypto.*
import com.nesbit.crypto.sphinx.SphinxPublicIdentity.Companion.CHAIN_HASH_ID
import com.nesbit.crypto.sphinx.SphinxPublicIdentity.Companion.MAX_CHAIN_LENGTH
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class SphinxPublicIdentity(val signingPublicKey: PublicKey, val diffieHellmanPublicKey: PublicKey, val targetHash: SecureHash) {
    companion object {
        val ID_HASH_ALGORITHM = "SHA-256"
        val CHAIN_HASH_ID = "HmacSHA256"
        val MAX_CHAIN_LENGTH = 65536
    }
    init {
        require(diffieHellmanPublicKey.algorithm == "Curve25519")
    }

    val id: SecureHash by lazy {
        val bytes = concatByteArrays(signingPublicKey.encoded, diffieHellmanPublicKey.encoded, targetHash.bytes)
        bytes.secureHash(ID_HASH_ALGORITHM)
    }

    private val chainKey: SecretKeySpec by lazy {
        SecretKeySpec(concatByteArrays(signingPublicKey.encoded, diffieHellmanPublicKey.encoded), CHAIN_HASH_ID)
    }

    fun verifyChainValue(hashBytes: ByteArray, stepsFromEnd: Int): Boolean {
        if (stepsFromEnd > MAX_CHAIN_LENGTH) {
            return false
        }
        val hmac = Mac.getInstance(CHAIN_HASH_ID)
        val endHash = hashBytes.copyOf()
        hmac.init(chainKey)
        for (i in 0 until stepsFromEnd) {
            hmac.update(endHash)
            hmac.doFinal(endHash, 0)
        }
        return Arrays.equals(targetHash.bytes, endHash)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SphinxPublicIdentity

        if (id != other.id) return false

        return true
    }

    override fun hashCode(): Int {
        return id.hashCode()
    }
}

class SphinxIdentityKeyPair(val signingKeys: KeyPair, val diffieHellmanKeys: KeyPair, val hashChain: Pair<SecureHash, SecureHash>) {
    companion object {
        fun generateKeyPair(secureRandom: SecureRandom = newSecureRandom()): SphinxIdentityKeyPair {
            val signingKeys = generateEdDSAKeyPair(secureRandom)
            val dhKeys = generateCurve25519DHKeyPair(secureRandom)
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(concatByteArrays(signingKeys.public.encoded, dhKeys.public.encoded), CHAIN_HASH_ID)
            val endVal = getChainValueInternal(0, startHash, hmacKey)
            return SphinxIdentityKeyPair(signingKeys, dhKeys, Pair(endVal, startHash))
        }

        private fun getChainValueInternal(stepsFromEnd: Int, seed: SecureHash, hmacKey: SecretKeySpec): SecureHash {
            require(stepsFromEnd <= MAX_CHAIN_LENGTH)
            val hmac = Mac.getInstance(CHAIN_HASH_ID)
            val endHash = seed.bytes.copyOf()
            hmac.init(hmacKey)
            for (i in 0 until (MAX_CHAIN_LENGTH - stepsFromEnd)) {
                hmac.update(endHash)
                hmac.doFinal(endHash, 0)
            }
            return SecureHash(CHAIN_HASH_ID, endHash)
        }
    }

    init {
        require(diffieHellmanKeys.private.algorithm == "Curve25519")
    }

    private val chainKey: SecretKeySpec by lazy {
        SecretKeySpec(concatByteArrays(signingKeys.public.encoded, diffieHellmanKeys.public.encoded), CHAIN_HASH_ID)
    }

    fun getChainValue(stepsFromEnd: Int): SecureHash = getChainValueInternal(stepsFromEnd, hashChain.second, chainKey)

    val public: SphinxPublicIdentity by lazy { SphinxPublicIdentity(signingKeys.public, diffieHellmanKeys.public, hashChain.first) }

    val id: SecureHash get() = public.id
}