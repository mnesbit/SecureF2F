package uk.co.nesbit.crypto

import java.lang.management.ManagementFactory
import java.nio.ByteBuffer
import kotlin.experimental.xor


fun concatByteArrays(vararg concat: ByteArray): ByteArray {
    if (concat.isEmpty()) {
        return ByteArray(0)
    }
    val length = concat.sumOf { it.size }
    val output = ByteArray(length)
    var offset = 0
    for (segment in concat) {
        val segmentSize = segment.size
        System.arraycopy(segment, 0, output, offset, segmentSize)
        offset += segmentSize
    }
    return output
}

fun ByteArray.splitByteArrays(vararg lengths: Int): List<ByteArray> {
    require(lengths.sum() == this.size) { "Array length ${this.size} doesn't match split lengths ${lengths.sum()}" }
    var start = 0
    val splits = mutableListOf<ByteArray>()
    for (length in lengths) {
        splits.add(this.copyOfRange(start, start + length))
        start += length
    }
    return splits
}

fun xorByteArrays(array1: ByteArray, array2: ByteArray): ByteArray {
    require(array1.size == array2.size) { "Only able to Xor same size arrays" }
    val output = ByteArray(array1.size)
    for (i in 0 until array1.size) {
        output[i] = array1[i] xor array2[i]
    }
    return output
}

fun byteArrayFromInts(vararg values: Int): ByteArray = ByteArray(values.size) { values[it].toByte() }

fun Int.toByteArray(): ByteArray {
    return byteArrayOf((this shr 24).toByte(), (this shr 16).toByte(), (this shr 8).toByte(), this.toByte())
}

fun Long.toByteArray(): ByteArray {
    val buffer = ByteBuffer.allocate(java.lang.Long.BYTES)
    buffer.putLong(this)
    return buffer.array()
}

fun ByteArray.toInt(): Int {
    require(this.size == 4) {
        "Invalid buffer size"
    }
    return ByteBuffer.wrap(this).getInt()
}

fun ByteArray.toLong(): Long {
    require(this.size == 8) {
        "Invalid buffer size"
    }
    return ByteBuffer.wrap(this).getLong()
}

fun getGCStats(): Long {
    var totalGarbageCollections: Long = 0
    for (gc in ManagementFactory.getGarbageCollectorMXBeans()) {
        val count = gc.collectionCount
        if (count >= 0) {
            totalGarbageCollections += count
        }
    }
    return totalGarbageCollections
}
