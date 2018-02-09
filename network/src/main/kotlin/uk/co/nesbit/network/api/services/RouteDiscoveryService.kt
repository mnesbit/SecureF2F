package uk.co.nesbit.network.api.services

import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.Route
import uk.co.nesbit.network.api.RouteState

interface RouteDiscoveryService {
    val routes: Map<Route, RouteState>
    val knownAddresses: Set<Address>
    fun findRandomRouteTo(destination: Address): List<Address>?

    fun nextGossip()
}