package com.nesbit.network.engine

import com.nesbit.network.api.Address
import com.nesbit.network.api.LinkId
import com.nesbit.network.api.LinkInfo
import com.nesbit.network.api.LinkStatusChange
import com.nesbit.network.api.services.KeyService
import com.nesbit.network.api.services.NeighbourDiscoveryService
import com.nesbit.network.api.services.NetworkService
import rx.Observable
import rx.subjects.PublishSubject

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