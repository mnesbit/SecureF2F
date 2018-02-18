package uk.co.nesbit.network.api

import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import java.security.PublicKey

interface Address

data class NetworkAddress(val id: Int) : Address

data class PublicAddress(val host: String, val port: Int) : Address

data class SphinxAddress(val identity: SphinxPublicIdentity) : Address {
    val id: SecureHash get() = identity.id
}

data class OverlayAddress(val identity: PublicKey) : Address
