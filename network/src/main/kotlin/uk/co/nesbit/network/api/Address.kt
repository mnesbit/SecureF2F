package uk.co.nesbit.network.api

interface Address

data class VersionedAddress(val address: Address, val version: Int)

data class NetworkAddress(val id: Int) : Address {
    override fun toString(): String = "NetworkAddress[$id]"
}

data class OverlayAddress(val id: Int) : Address {
    override fun toString(): String = "OverlayAddress[$id]"
}
