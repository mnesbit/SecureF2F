package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.subjects.PublishSubject
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.LinkInfo
import uk.co.nesbit.network.api.LinkStatusChange
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.NeighbourDiscoveryService
import uk.co.nesbit.network.api.services.NetworkService

class NeighbourDiscoveryServiceImpl(val network: NetworkService, val identityService: KeyService) : NeighbourDiscoveryService {
    override val links: MutableMap<LinkId, LinkInfo> = mutableMapOf()

    override val knownNeighbours: MutableSet<Address> = mutableSetOf()

    private val _onLinkStatusChange = PublishSubject.create<LinkStatusChange>()
    override val onLinkStatusChange: Observable<LinkStatusChange>
        get() = _onLinkStatusChange

    init {

    }

    override fun nextPing() {
    }
}