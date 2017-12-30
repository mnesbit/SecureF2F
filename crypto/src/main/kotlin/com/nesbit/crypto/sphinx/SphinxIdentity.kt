package com.nesbit.crypto.sphinx

import com.nesbit.crypto.*
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom

class SphinxPublicIdentity(val signingPublicKey: PublicKey, val diffieHellmanPublicKey: PublicKey, val hashChain: HashChainPublic, val publicAddress: String?) {
    companion object {
        val ID_HASH_ALGORITHM = "SHA-256"
    }

    init {
        require(diffieHellmanPublicKey.algorithm == "Curve25519")
    }

    fun serialize(): ByteArray {
        val addressLength = publicAddress?.length ?: 0
        val addressBytes = ByteArray(addressLength + 4)
        val buf = ByteBuffer.wrap(addressBytes)
        buf.putInt(addressLength)
        if (publicAddress != null) {
            buf.put(publicAddress.toByteArray(Charsets.UTF_8))
        }
        return concatByteArrays(signingPublicKey.encoded, diffieHellmanPublicKey.encoded, hashChain.targetHash.bytes, addressBytes)
    }

    val id: SecureHash by lazy {
        val bytes = serialize()
        bytes.secureHash(ID_HASH_ALGORITHM)
    }

    fun verifyChainValue(hashBytes: ByteArray, stepsFromEnd: Int): Boolean = hashChain.verifyChainValue(hashBytes, stepsFromEnd)

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int): Boolean = hashChain.verifyChainValue(hash, stepsFromEnd)

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

class SphinxIdentityKeyPair(val signingKeys: KeyPair, val diffieHellmanKeys: KeyPair, val hashChain: HashChainPrivate, val publicAddress: String? = null) {
    companion object {
        fun generateKeyPair(secureRandom: SecureRandom = newSecureRandom(), publicAddress: String? = null): SphinxIdentityKeyPair {
            val signingKeys = generateEdDSAKeyPair(secureRandom)
            val dhKeys = generateCurve25519DHKeyPair(secureRandom)
            val hashChain = HashChainPrivate.generateChain(concatByteArrays(signingKeys.public.encoded, dhKeys.public.encoded), secureRandom)
            return SphinxIdentityKeyPair(signingKeys, dhKeys, hashChain, publicAddress)
        }
    }

    init {
        require(diffieHellmanKeys.private.algorithm == "Curve25519")
    }

    fun getChainValue(stepsFromEnd: Int): SecureHash = hashChain.getChainValue(stepsFromEnd)

    val public: SphinxPublicIdentity by lazy { SphinxPublicIdentity(signingKeys.public, diffieHellmanKeys.public, hashChain.public, publicAddress) }

    val id: SecureHash get() = public.id
}