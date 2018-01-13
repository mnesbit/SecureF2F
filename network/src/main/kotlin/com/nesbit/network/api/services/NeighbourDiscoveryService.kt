package com.nesbit.network.api.services

import com.nesbit.network.api.Address
import com.nesbit.network.api.LinkId
import com.nesbit.network.api.LinkInfo
import com.nesbit.network.api.LinkStatusChange
import rx.Observable

interface NeighbourDiscoveryService {
    val links: Map<LinkId, LinkInfo>
    val knownNeighbours: Set<Address>
    val onLinkStatusChange: Observable<LinkStatusChange>

    fun nextPing()
}