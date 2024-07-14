package uk.co.nesbit.network.api

import uk.co.nesbit.utils.printHexBinary
import java.net.URI
import java.net.URL
import java.security.PublicKey
import java.util.*

interface Address {
    val actorName: String
}

class NetworkAddress(val id: Int) : Address {
    override val actorName: String get() = id.toString()

    fun toLocalPublicAddress(): PublicAddress = PublicAddress("localhost", id + 20000)

    fun toLocalHTTPSAddress(): URLAddress =
        URLAddress(URI(URLAddress.HTTPS_PROTOCOL, null, "localhost", id + 20000, "", null, null).toURL())

    override fun toString(): String = "NetworkAddress[$id]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NetworkAddress

        if (id != other.id) return false

        return true
    }

    override fun hashCode(): Int {
        return id
    }
}

class PublicAddress(val host: String, val port: Int) : Address {
    override val actorName: String get() = "$host:$port"

    override fun toString(): String = "PublicAddress[$host:$port]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicAddress

        if (host.uppercase(Locale.getDefault()) != other.host.uppercase(Locale.getDefault())) return false
        if (port != other.port) return false

        return true
    }

    override fun hashCode(): Int {
        var result = host.uppercase(Locale.getDefault()).hashCode()
        result = 31 * result + port
        return result
    }
}

class URLAddress(val url: URL) : Address {
    companion object {
        const val HTTPS_PROTOCOL = "https"
    }

    init {
        require(url.protocol == HTTPS_PROTOCOL) {
            "Only HTTPS currently implemented"
        }
    }

    override val actorName: String get() = "${url.protocol}_${url.host}_${url.port}${url.file.replace("[^-\\w:@&=+,.!~*'_;]".toRegex(), "_")}"

    override fun toString(): String = "URLAddress[$url]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as URLAddress

        if (url != other.url) return false

        return true
    }

    override fun hashCode(): Int {
        return url.hashCode()
    }
}

class OverlayAddress(val identity: PublicKey) : Address {
    override val actorName: String get() = identity.encoded.printHexBinary()

    override fun toString(): String = "OverlayAddress[$identity]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as OverlayAddress

        if (identity.encoded!!.contentEquals(other.identity.encoded)) return false

        return true
    }

    override fun hashCode(): Int {
        return identity.encoded.hashCode()
    }
}
