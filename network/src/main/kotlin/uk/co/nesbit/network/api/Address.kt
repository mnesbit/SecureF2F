package uk.co.nesbit.network.api

import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.utils.printHexBinary
import java.security.PublicKey

interface Address {
    val actorName: String
}

class NetworkAddress(val id: Int) : Address {
    override val actorName: String get() = id.toString()

    fun toLocalPublicAddress(): PublicAddress = PublicAddress("localhost", id + 10000)

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

        if (host.toUpperCase() != other.host.toUpperCase()) return false
        if (port != other.port) return false

        return true
    }

    override fun hashCode(): Int {
        var result = host.toUpperCase().hashCode()
        result = 31 * result + port
        return result
    }
}

class SphinxAddress(val identity: SphinxPublicIdentity) : Address {
    val id: SecureHash get() = identity.id

    override val actorName: String get() = identity.id.bytes.printHexBinary()

    override fun toString(): String =
            if (identity.publicAddress == null) "Sphinx[$id]" else "Sphinx[${identity.publicAddress}]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SphinxAddress

        if (identity != other.identity) return false

        return true
    }

    override fun hashCode(): Int {
        return identity.hashCode()
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
