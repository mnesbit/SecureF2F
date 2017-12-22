package com.nesbit.crypto

import kotlin.experimental.xor


fun concatByteArrays(vararg concat: ByteArray): ByteArray {
    if (concat.isEmpty()) {
        return ByteArray(0)
    }
    val length = concat.sumBy { it.size }
    val output = ByteArray(length)
    var offset = 0
    for (segment in concat) {
        val segmentSize = segment.size
        System.arraycopy(segment, 0, output, offset, segmentSize)
        offset += segmentSize
    }
    return output
}

fun xorByteArrays(array1: ByteArray, array2: ByteArray): ByteArray {
    require(array1.size == array2.size) { "Only able to Xor same size arrays" }
    val output = ByteArray(array1.size)
    for (i in 0 until array1.size) {
        output[i] = array1[i] xor array2[i]
    }
    return output
}

fun ByteArray.printHex() = javax.xml.bind.DatatypeConverter.printHexBinary(this)

