package uk.co.nesbit.network.api.services

import io.reactivex.Observable
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.routing.Routes

data class NeighbourReceivedMessage(val source: Address, val msg: ByteArray)

interface NeighbourDiscoveryService {
    val networkAddress: SphinxAddress
    val links: Map<LinkId, LinkInfo>
    val routes: Routes
    val knownNeighbours: Set<Address>
    val onLinkStatusChange: Observable<LinkStatusChange>

    fun findLinkTo(neighbourAddress: Address): LinkId?
    fun send(linkId: LinkId, msg: ByteArray)
    val onReceive: Observable<NeighbourReceivedMessage>

    fun runStateMachine()
}