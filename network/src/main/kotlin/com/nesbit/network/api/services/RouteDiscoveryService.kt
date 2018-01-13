package com.nesbit.network.api.services

import com.nesbit.network.api.Address
import com.nesbit.network.api.Route
import com.nesbit.network.api.RouteState

interface RouteDiscoveryService {
    val routes: Map<Route, RouteState>
    val knownAddresses: Set<Address>
    fun findRandomRouteTo(destination: Address): List<Address>?

    fun nextGossip()
}