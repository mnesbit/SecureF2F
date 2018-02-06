package com.nesbit.avro

import org.apache.avro.io.Decoder
import org.apache.avro.util.Utf8
import java.io.EOFException
import java.io.IOException
import java.nio.ByteBuffer

// The BinaryDecoder that comes with Avro can stupidly allocate byte buffers bigger than the possible payload causing OutOfMemoryExceptions
// This simpler version demands a bounded source ByteArray and length checks always
class SafeDecoder(private val source: ByteArray) : Decoder() {
    private var index: Int = 0

    val fullyConsumed: Boolean get() = (index == source.size)

    private fun getNextUnsignedByte(): Int {
        if (index >= source.size) {
            throw EOFException()
        }
        return source[index++].toInt() and 0xFF
    }

    override fun readNull() {
        //NOOP
    }

    @Throws(IOException::class)
    override fun readInt(): Int {
        var n = 0
        var b: Int
        var shift = 0
        do {
            b = getNextUnsignedByte()
            if (b >= 0) {
                n = n or ((b and 0x7F) shl shift)
                if (b and 0x80 == 0) {
                    return n.ushr(1) xor -(n and 1) // back to two's-complement
                }
            } else {
                throw EOFException()
            }
            shift += 7
        } while (shift < 32)

        throw IOException("Invalid int encoding")
    }

    @Throws(IOException::class)
    override fun readLong(): Long {
        var n: Long = 0
        var b: Long
        var shift = 0
        do {
            b = getNextUnsignedByte().toLong()
            if (b >= 0) {
                n = n or ((b and 0x7FL) shl shift)
                if (b and 0x80L == 0L) {
                    return n.ushr(1) xor -(n and 1) // back to two's-complement
                }
            } else {
                throw EOFException()
            }
            shift += 7
        } while (shift < 64)
        throw IOException("Invalid long encoding")
    }

    override fun readFloat(): Float {
        val b0 = getNextUnsignedByte()
        val b1 = getNextUnsignedByte()
        val b2 = getNextUnsignedByte()
        val b3 = getNextUnsignedByte()

        val n = b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
        return java.lang.Float.intBitsToFloat(n)
    }

    override fun readDouble(): Double {
        val b0 = getNextUnsignedByte().toLong()
        val b1 = getNextUnsignedByte().toLong()
        val b2 = getNextUnsignedByte().toLong()
        val b3 = getNextUnsignedByte().toLong()
        val b4 = getNextUnsignedByte().toLong()
        val b5 = getNextUnsignedByte().toLong()
        val b6 = getNextUnsignedByte().toLong()
        val b7 = getNextUnsignedByte().toLong()

        val n = b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24) or
                (b4 shl 32) or (b5 shl 40) or (b6 shl 48) or (b7 shl 56)
        return java.lang.Double.longBitsToDouble(n)
    }

    @Throws(IOException::class)
    override fun readString(old: Utf8?): Utf8 {
        val length = readInt()
        val result = old ?: Utf8()
        result.byteLength = length
        if ((length < 0) || (length + index > source.size)) {
            throw IOException()
        }
        if (length > 0) {
            System.arraycopy(source, index, result.bytes, 0, length)
            index += length
        }
        return result
    }

    @Throws(IOException::class)
    override fun readString(): String {
        return readString(null).toString()
    }

    @Throws(IOException::class)
    override fun skipString() {
        val length = readInt()
        if ((length < 0) || (length + index > source.size)) {
            throw IOException()
        }
        index += length
    }

    @Throws(IOException::class)
    override fun readBytes(old: ByteBuffer?): ByteBuffer {
        val length = readInt()
        if ((length < 0) || (length + index > source.size)) {
            throw IOException()
        }
        val result: ByteBuffer

        if (old != null && length <= old.capacity()) {
            result = old
            result.clear()
        } else {
            result = ByteBuffer.allocate(length)
        }

        if (length > 0) {
            result.put(source, index, length)
            index += length
        }
        result.limit(length)
        result.flip()

        return result
    }

    @Throws(IOException::class)
    override fun skipBytes() {
        val length = readInt()
        if ((length < 0) || (length + index > source.size)) {
            throw IOException()
        }
        index += length
    }

    @Throws(IOException::class)
    override fun readBoolean(): Boolean {
        val b = getNextUnsignedByte()
        if (b == 0) {
            return false
        } else if (b == 1) {
            return true
        }
        throw IOException()
    }

    @Throws(IOException::class)
    override fun readEnum(): Int {
        return readInt()
    }

    @Throws(IOException::class)
    override fun readFixed(bytes: ByteArray, start: Int, length: Int) {
        if ((length < 0) || (length + index > source.size)) {
            throw IOException()
        }
        System.arraycopy(source, index, bytes, start, length)
        index += length
    }

    @Throws(IOException::class)
    override fun skipFixed(length: Int) {
        if ((length < 0) || (length + index > source.size)) {
            throw IOException()
        }
        index += length
    }

    override fun readIndex(): Int {
        return readInt()
    }

    override fun readMapStart(): Long {
        return doReadItemCount()
    }

    override fun mapNext(): Long {
        return doReadItemCount()
    }

    override fun skipMap(): Long {
        return doSkipItems()
    }

    override fun readArrayStart(): Long {
        return doReadItemCount()
    }

    override fun arrayNext(): Long {
        return doReadItemCount()
    }

    override fun skipArray(): Long {
        return doSkipItems()
    }

    @Throws(IOException::class)
    private fun doReadItemCount(): Long {
        var result = readLong()
        if (result < 0) {
            readLong() // Consume byte-count if present
            result = -result
        }
        return result
    }

    @Throws(IOException::class)
    private fun doSkipItems(): Long {
        var result = readInt()
        while (result < 0) {
            val bytecount = readLong()
            if ((bytecount < 0) || (bytecount > Int.MAX_VALUE.toLong())) {
                throw IOException()
            }
            skipFixed(bytecount.toInt())
            result = readInt()
        }
        return result.toLong()
    }

}