package com.nesbit.crypto

import com.nesbit.crypto.HashChainPublic.Companion.CHAIN_HASH_ID
import com.nesbit.crypto.HashChainPublic.Companion.MAX_CHAIN_LENGTH
import java.security.SecureRandom
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class HashChainPublic(val chainKey: SecretKeySpec, val targetHash: SecureHash) {
    constructor(keyMaterial: ByteArray, targetHash: SecureHash) : this(SecretKeySpec(keyMaterial, CHAIN_HASH_ID), targetHash)

    companion object {
        val CHAIN_HASH_ID = "HmacSHA256"
        val MAX_CHAIN_LENGTH = 65536
    }

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int): Boolean {
        require(hash.algorithm == CHAIN_HASH_ID)
        return verifyChainValue(hash.bytes, stepsFromEnd)
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
}

class HashChainPrivate(val chainKey: SecretKeySpec, val targetHash: SecureHash, val seedHash: SecureHash, var version: Int) {
    companion object {
        fun generateChain(keyMaterial: ByteArray, secureRandom: SecureRandom = newSecureRandom()): HashChainPrivate {
            val seed = ByteArray(32)
            secureRandom.nextBytes(seed)
            val startHash = SecureHash(CHAIN_HASH_ID, seed)
            val hmacKey = SecretKeySpec(keyMaterial, CHAIN_HASH_ID)
            val endVal = getChainValueInternal(0, startHash, hmacKey)
            return HashChainPrivate(hmacKey, endVal, startHash, 0)
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

    fun getChainValue(stepsFromEnd: Int): SecureHash {
        require(stepsFromEnd <= MAX_CHAIN_LENGTH)
        require(stepsFromEnd >= version) { "Version $stepsFromEnd already used. Current version $version" }
        version = maxOf(stepsFromEnd, version)
        return getChainValueInternal(stepsFromEnd, seedHash, chainKey)
    }

    val public: HashChainPublic by lazy { HashChainPublic(chainKey, targetHash) }

}