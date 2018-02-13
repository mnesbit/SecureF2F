package uk.co.nesbit.network.api

data class Route(val from: Address, val to: Address)

data class RouteState(val route: Route, val status: LinkStatus) {
    override fun toString(): String = "${route.from}${if (status.active()) "->" else "X"}${route.to}"
}

data class LinkInfo(val linkId: LinkId, val state: RouteState)
