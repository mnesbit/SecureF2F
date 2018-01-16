package com.nesbit.network.api.services

import com.nesbit.network.api.Address

interface NameDiscoveryService {
    val knownAddresses: Set<Address>
    fun mapToNetworkAddress(targetAddress: Address): Address?
}