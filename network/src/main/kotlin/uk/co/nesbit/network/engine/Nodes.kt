package uk.co.nesbit.network.engine

import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.NeighbourDiscoveryService
import uk.co.nesbit.network.api.services.NetworkService
import uk.co.nesbit.network.api.services.RouteDiscoveryService

class Layer1Node(networkService: NetworkService) {
    val keyService: KeyService = KeyServiceImpl()
    val neighbourDiscoveryService: NeighbourDiscoveryService = NeighbourDiscoveryServiceImpl(networkService, keyService)
    val networkAddress: SphinxAddress get() = neighbourDiscoveryService.networkAddress

    fun runStateMachine() {
        neighbourDiscoveryService.runStateMachine()
    }
}

class Layer2Node(networkService: NetworkService) {
    val keyService: KeyService = KeyServiceImpl()
    val neighbourDiscoveryService: NeighbourDiscoveryService = NeighbourDiscoveryServiceImpl(networkService, keyService)
    val routeDiscoveryService: RouteDiscoveryService = RouteDiscoveryServiceImpl(neighbourDiscoveryService, keyService)

    fun runStateMachine() {
        neighbourDiscoveryService.runStateMachine()
        routeDiscoveryService.runStateMachine()
    }
}