package com.nesbit.crypto

import djb.Curve25519
import java.security.SecureRandom
import java.util.*

class Curve25519PublicKey(val keyBytes: ByteArray) {
    init {
        require(keyBytes.size == Curve25519.KEY_SIZE) {
            "Curve25519 keys must be 32 bytes long"
        }
    }

    override fun toString(): String = "PUB25519:${keyBytes.printHex()}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Curve25519PublicKey

        if (!Arrays.equals(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }
}

class Curve25519PrivateKey(val keyBytes: ByteArray) {
    init {
        require(keyBytes.size == Curve25519.KEY_SIZE) {
            "Curve25519 keys must be 32 bytes long"
        }
        Curve25519.clamp(keyBytes) // ensure it is a valid private key
    }

    override fun toString(): String = "PRV25519:${keyBytes.printHex()}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Curve25519PrivateKey

        if (!Arrays.equals(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }
}

class Curve25519KeyPair(val publicKey: Curve25519PublicKey, val privateKey: Curve25519PrivateKey) {
    companion object {
        fun generateKeyPair(secureRandom: SecureRandom = newSecureRandom()): Curve25519KeyPair {
            val privateKeyBytes = ByteArray(Curve25519.KEY_SIZE)
            val publicKeyBytes = ByteArray(Curve25519.KEY_SIZE)
            secureRandom.nextBytes(privateKeyBytes)
            Curve25519.keygen(publicKeyBytes, null, privateKeyBytes)
            return Curve25519KeyPair(Curve25519PublicKey(publicKeyBytes), Curve25519PrivateKey(privateKeyBytes))
        }
    }

    override fun toString(): String = "$publicKey\n$privateKey"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Curve25519KeyPair

        if (publicKey != other.publicKey) return false
        if (privateKey != other.privateKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.hashCode()
        result = 31 * result + privateKey.hashCode()
        return result
    }
}

fun generateSharedECDHSecret(publicInfo: Curve25519PublicKey, privateInfo: Curve25519PrivateKey): Curve25519PublicKey {
    val secret = ByteArray(Curve25519.KEY_SIZE)
    Curve25519.curve(secret, privateInfo.keyBytes, publicInfo.keyBytes)
    return Curve25519PublicKey(secret)
}