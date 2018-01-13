package com.nesbit.network.api

enum class LinkStatus {
    LINK_UP,
    LINK_DOWN
}

data class LinkStatusChange(val linkId: LinkId, val status: LinkStatus)
