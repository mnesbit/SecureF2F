package uk.co.nesbit.network.api

import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import java.security.PublicKey

interface Address

data class NetworkAddress(val id: Int) : Address {
    override fun toString(): String = "NetworkAddress[$id]"
}

data class PublicAddress(val host: String, val port: Int) : Address {
    override fun toString(): String = "PublicAddress[$host:$port]"
}

data class SphinxAddress(val identity: SphinxPublicIdentity) : Address {
    val id: SecureHash get() = identity.id

    override fun toString(): String = if (identity.publicAddress == null) "Sphinx[$id]" else "Sphinx[${identity.publicAddress}]"
}

data class OverlayAddress(val identity: PublicKey) : Address {
    override fun toString(): String = "OverlayAddress[$identity]"
}