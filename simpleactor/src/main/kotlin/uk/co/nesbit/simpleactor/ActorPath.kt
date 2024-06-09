package uk.co.nesbit.simpleactor

import kotlin.math.max

data class ActorPath(val address: String) {
    val parent: ActorPath by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val systemIndex = address.indexOf("//")
        var rootIndex = address.indexOf("/", systemIndex + 2)
        if (rootIndex == -1) {
            rootIndex = address.length
        }
        val index = address.lastIndexOf('/')
        ActorPath(address.substring(0, max(index, rootIndex)))
    }

    val name: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        address.substring(address.lastIndexOf("/") + 1, address.length)
    }

    fun child(name: String): ActorPath = ActorPath("$address/$name")

    override fun toString(): String = address
}