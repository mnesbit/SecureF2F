package uk.co.nesbit.crypto

import java.util.*

class ComparableByteArray(val bytes: ByteArray) : Comparable<ComparableByteArray> {
    override fun compareTo(other: ComparableByteArray): Int {
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

    override fun toString(): String = bytes.printHex()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ComparableByteArray

        if (!Arrays.equals(bytes, other.bytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(bytes)
    }
}