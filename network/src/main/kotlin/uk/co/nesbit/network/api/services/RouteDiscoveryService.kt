package uk.co.nesbit.network.api.services

import io.reactivex.Observable
import uk.co.nesbit.network.api.Address

class RouteReceivedMessage(val source: Address, val msg: ByteArray)

interface RouteDiscoveryService {
    val knownAddresses: Set<Address>
    fun findRandomRouteTo(destination: Address): List<Address>?
    fun send(route: List<Address>, msg: ByteArray)
    val onReceive: Observable<RouteReceivedMessage>

    fun runStateMachine()
}