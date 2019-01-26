package uk.co.nesbit.network.api.services

import uk.co.nesbit.network.api.Address

interface NameDiscoveryService {
    val knownAddresses: Set<Address>
    fun mapToNetworkAddress(targetAddress: Address): Address?
}