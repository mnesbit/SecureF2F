package uk.co.nesbit.network.engineOld

import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.NeighbourDiscoveryService
import uk.co.nesbit.network.api.services.NetworkService
import uk.co.nesbit.network.api.services.RouteDiscoveryService

class Layer1Node(networkService: NetworkService,
                 maxVersion: Int = 128) {
    val keyService: KeyService = KeyServiceImpl(maxVersion = maxVersion)
    val neighbourDiscoveryService: NeighbourDiscoveryService = NeighbourDiscoveryServiceImpl(networkService, keyService)
    val networkAddress: SphinxAddress get() = neighbourDiscoveryService.networkAddress

    fun runStateMachine() {
        neighbourDiscoveryService.runStateMachine()
    }
}

class Layer2Node(networkService: NetworkService,
                 val routeGossipInterval: Int = 4,
                 maxVersion: Int = 128) {
    val networkId: Address = networkService.networkId
    val keyService: KeyService = KeyServiceImpl(maxVersion = maxVersion)
    val neighbourDiscoveryService: NeighbourDiscoveryService = NeighbourDiscoveryServiceImpl(networkService, keyService)
    val routeDiscoveryService: RouteDiscoveryService = RouteDiscoveryServiceImpl(neighbourDiscoveryService, keyService)
    var divider: Int = 0

    fun runStateMachine() {
        neighbourDiscoveryService.runStateMachine()
        if (divider % routeGossipInterval == 0) {
            routeDiscoveryService.runStateMachine()
        }
        divider++
    }
}