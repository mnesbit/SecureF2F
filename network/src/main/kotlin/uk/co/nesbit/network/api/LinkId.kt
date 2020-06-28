package uk.co.nesbit.network.api

interface LinkId {
    val id: Int
}

data class SimpleLinkId(override val id: Int) : LinkId
