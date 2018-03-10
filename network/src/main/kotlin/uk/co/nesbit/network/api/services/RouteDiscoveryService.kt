package uk.co.nesbit.network.api.services

import io.reactivex.Observable
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.routing.RoutedMessage

interface RouteDiscoveryService {
    val knownAddresses: Set<Address>
    fun findRandomRouteTo(destination: Address): List<Address>?
    fun send(route: List<Address>, msg: RoutedMessage)
    val onReceive: Observable<RoutedMessage>

    fun runStateMachine()
}