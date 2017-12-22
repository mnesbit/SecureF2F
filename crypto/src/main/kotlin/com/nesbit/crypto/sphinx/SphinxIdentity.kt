package com.nesbit.crypto.sphinx

import com.nesbit.crypto.*
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom

class SphinxPublicIdentity(val signingPublicKey: PublicKey, val diffieHellmanPublicKey: PublicKey) {
    val id: ComparableByteArray by lazy {
        val bytes = concatByteArrays(signingPublicKey.encoded, diffieHellmanPublicKey.encoded)
        ComparableByteArray(bytes.secureHash().bytes)
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

    val publicKeys: SphinxPublicIdentity get() = SphinxPublicIdentity(signingKeys.public, diffieHellmanKeys.public)
}