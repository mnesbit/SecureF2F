package uk.co.nesbit.utils

import java.io.InputStream
import java.nio.charset.Charset

fun InputStream.readTextAndClose(charset: Charset = Charsets.UTF_8): String {
    return this.bufferedReader(charset).use { it.readText() }
}

fun ByteArray.printHexBinary(): String {
    fun digitChar(digit: Int): Char = if (digit < 10) ('0' + digit) else ('A' + digit - 10)

    val buf = StringBuilder(2 * this.size)
    for (ch in this) {
        val low = ch.toInt() and 0x0F
        val high = (ch.toInt() shr 4) and 0x0F
        buf.append(digitChar(high))
        buf.append(digitChar(low))
    }
    return buf.toString()
}

fun <R> printTime(str: String, block: () -> R): R {
    val start = System.nanoTime()
    val result = block()
    val end = System.nanoTime()
    println("$str ${(end - start) / 1000L}")
    return result
}