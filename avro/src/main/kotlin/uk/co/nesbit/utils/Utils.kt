package uk.co.nesbit.utils

import java.io.File
import java.io.InputStream
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.Charset
import java.util.jar.JarEntry
import java.util.jar.JarFile

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

fun String.decodeHex(): ByteArray {
    require(length % 2 == 0) { "Must have an even length" }

    return ByteArray(length / 2) {
        Integer.parseInt(this, it * 2, (it + 1) * 2, 16).toByte()
    }
}

fun <R> printTime(str: String, block: () -> R): R {
    val start = System.nanoTime()
    val result = block()
    val end = System.nanoTime()
    println("$str ${(end - start) / 1000L}")
    return result
}

fun resourceAsBytes(fileName: String, loader: ClassLoader): ByteArray? {
    loader.getResourceAsStream(fileName).use { input ->
        if (input == null) return null
        return input.readBytes()
    }
}

fun resourceAsString(fileName: String, loader: ClassLoader, charset: Charset = Charsets.UTF_8): String? {
    loader.getResourceAsStream(fileName).use { input ->
        if (input == null) return null
        return input.readTextAndClose(charset)
    }
}

fun resourcesFromFileDirectoryRecursive(
    path: URL,
    pattern: Regex,
    loader: ClassLoader,
    charset: Charset
): List<String> {
    val results = mutableListOf<String>()
    val baseItemFile = File(path.toURI())
    if (baseItemFile.isDirectory) {
        path.openConnection().getInputStream()?.use { stream ->
            stream.bufferedReader(charset).use { reader ->
                val children = reader.lines()
                for (child in children) {
                    val childPath = if (path.path.endsWith("/")) {
                        path.toURI().resolve(URLEncoder.encode(child, Charsets.UTF_8)).toURL()
                    } else {
                        path.toURI().resolve(path.toURI().path + "/" + URLEncoder.encode(child, Charsets.UTF_8)).toURL()
                    }
                    results += resourcesFromFileDirectoryRecursive(
                        childPath,
                        pattern,
                        loader,
                        charset
                    )
                }
            }
        }
    } else if (pattern.matchEntire(path.path) != null) {
        results += path.openConnection().getInputStream().readTextAndClose(charset)
    }
    return results
}

fun resourcesAsStringsRecursive(
    startPath: String,
    pattern: Regex,
    loader: ClassLoader,
    charset: Charset = Charsets.UTF_8
): List<String> {
    val results = mutableListOf<String>()
    val baseItems = loader.getResources(startPath)
    for (itemURL in baseItems) {
        if (itemURL.protocol == "jar") {
            val fullPath = itemURL.path
            val jarPath = fullPath.substring(5, fullPath.indexOf("!"))
            JarFile(URLDecoder.decode(jarPath, Charsets.UTF_8)).use { jarFile ->
                val entriesItr = jarFile.entries()
                for (entry: JarEntry in entriesItr) {
                    val entryName: String = entry.name
                    val pathIndex = entryName.lastIndexOf(startPath)
                    if (pathIndex >= 0) {
                        if (!entry.isDirectory) {
                            if (pattern.matchEntire(entryName) != null) {
                                results += jarFile.getInputStream(entry).readTextAndClose()
                            }
                        }
                    }
                }
            }
        } else {
            results += resourcesFromFileDirectoryRecursive(
                itemURL,
                pattern,
                loader,
                charset
            )
        }
    }
    return results
}
