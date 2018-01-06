package com.nesbit.network.api

data class Route(val from: Address, val to: Address)

data class RouteState(val route: Route, val version: Int, val status: LinkStatus) {
    override fun toString(): String = "${route.from}${if (status == LinkStatus.LINK_UP) "->" else "X"}${route.to}v$version"
}

data class LinkInfo(val linkId: LinkId, val state: RouteState)