package uk.co.nesbit.network.api

interface LifeCycle : AutoCloseable {
    fun start()
}