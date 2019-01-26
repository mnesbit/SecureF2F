package uk.co.nesbit.network.api

data class Route(val from: Address, val to: Address)

data class LinkInfo(val linkId: LinkId, val route: Route, val status: LinkStatus) {
    override fun toString(): String = when (status) {
        LinkStatus.LINK_DOWN -> "${route.from}X${route.to}"
        LinkStatus.LINK_UP_ACTIVE -> "${route.from}->${route.to}"
        LinkStatus.LINK_UP_PASSIVE -> "${route.from}<-${route.to}"
    }
}
