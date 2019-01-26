package uk.co.nesbit.network.api

enum class LinkStatus {
    LINK_DOWN,
    LINK_UP_PASSIVE,
    LINK_UP_ACTIVE
}

val LinkStatus.active: Boolean get() = (this != LinkStatus.LINK_DOWN)
