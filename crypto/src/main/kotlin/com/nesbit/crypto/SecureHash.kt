package com.nesbit.crypto

import java.security.MessageDigest
import java.util.*

data class SecureHash(val algorithm: String, val bytes: ByteArray) : Comparable<SecureHash> {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other?.javaClass != javaClass) return false

        other as SecureHash
        if (algorithm != other.algorithm) return false
        if (!Arrays.equals(bytes, other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(bytes) + 31 * algorithm.hashCode()
    }

    override fun toString(): String = "$algorithm[${bytes.printHex()}]"

    override fun compareTo(other: SecureHash): Int {
        var i = 0
        while (i < bytes.size && i < other.bytes.size) {
            if (bytes[i] < other.bytes[i]) {
                return -1
            } else if (bytes[i] > other.bytes[i]) {
                return 1
            }
            ++i
        }
        if (bytes.size < other.bytes.size) {
            return -1
        } else if (bytes.size > other.bytes.size) {
            return 1
        }
        return 0
    }

    companion object {
        fun secureHash(bits: ByteArray, algorithm: String = "SHA-256"): SecureHash = SecureHash(algorithm, MessageDigest.getInstance(algorithm).digest(bits))
        fun secureHash(str: String, algorithm: String = "SHA-256") = secureHash(str.toByteArray(Charsets.UTF_8), algorithm)
    }
}

fun ByteArray.secureHash(algorithm: String = "SHA-256") = SecureHash.secureHash(this, algorithm)
