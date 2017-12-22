package com.nesbit.crypto.sphinx

import com.nesbit.crypto.*
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom

class SphinxPublicIdentity(val signingPublicKey: PublicKey, val diffieHellmanPublicKey: PublicKey) {
    companion object {
        val ID_HASH_ALGORITH = "SHA-256"
    }
    init {
        require(diffieHellmanPublicKey.algorithm == "Curve25519")
    }

    val id: SecureHash by lazy {
        val bytes = concatByteArrays(signingPublicKey.encoded, diffieHellmanPublicKey.encoded)
        bytes.secureHash(ID_HASH_ALGORITH)
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

class SphinxIdentityKeyPair(val signingKeys: KeyPair, val diffieHellmanKeys: KeyPair) {
    companion object {
        fun generateKeyPair(secureRandom: SecureRandom = newSecureRandom()): SphinxIdentityKeyPair {
            return SphinxIdentityKeyPair(generateEdDSAKeyPair(secureRandom),
                    generateCurve25519DHKeyPair(secureRandom))
        }
    }

    init {
        require(diffieHellmanKeys.private.algorithm == "Curve25519")
    }

    val public: SphinxPublicIdentity by lazy { SphinxPublicIdentity(signingKeys.public, diffieHellmanKeys.public) }

    val id: SecureHash get() = public.id
}