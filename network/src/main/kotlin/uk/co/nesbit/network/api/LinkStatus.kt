package uk.co.nesbit.network.api

enum class LinkStatus {
    LINK_UP_ACTIVE,
    LINK_UP_PASSIVE,
    LINK_DOWN
}

fun LinkStatus.active(): Boolean = (this != LinkStatus.LINK_DOWN)
