package uk.co.nesbit.network.engine

import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.NeighbourDiscoveryService
import uk.co.nesbit.network.api.services.NetworkService

class Node(val networkService: NetworkService) {
    val keyService: KeyService = KeyServiceImpl()
    val neighbourDiscoveryService: NeighbourDiscoveryService = NeighbourDiscoveryServiceImpl(networkService, keyService)

    fun runStateMachine() {
        neighbourDiscoveryService.runStateMachine()
    }
}