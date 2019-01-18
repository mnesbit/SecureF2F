package uk.co.nesbit.network.api

enum class LinkStatus {
    LINK_UP_ACTIVE,
    LINK_UP_PASSIVE,
    LINK_DOWN
}

val LinkStatus.active: Boolean get() = (this != LinkStatus.LINK_DOWN)
