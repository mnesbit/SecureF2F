package com.nesbit.network.api

data class Route(val from: Address, val to: Address)

data class RouteState(val route: Route, val status: LinkStatus) {
    override fun toString(): String = "${route.from}${if (status == LinkStatus.LINK_UP) "->" else "X"}${route.to}"
}

data class LinkInfo(val linkId: LinkId, val state: RouteState)
