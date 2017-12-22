package com.nesbit.crypto

import djb.Curve25519
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*

class Curve25519PublicKey(val keyBytes: ByteArray) : PublicKey {
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

    override fun getAlgorithm(): String = "Curve25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}

class Curve25519PrivateKey(val keyBytes: ByteArray) : PrivateKey {
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

    override fun getAlgorithm(): String = "Curve25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}
