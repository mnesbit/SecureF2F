package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder

class NeighbourLinkActor(val physicalNetworkActor: ActorRef) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(physicalNetworkActor: ActorRef): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, physicalNetworkActor)
        }
    }

    override fun preStart() {
        super.preStart()
        log().info("Starting NeighbourLinkActor Actor")
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped NeighbourLinkActor Actor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart NeighbourLinkActor Actor")
    }

    override fun createReceive() =
        ReceiveBuilder()
            .match(String::class.java, this::onMessage)
            .build()

    private fun onMessage(message: String) {
        log().info(message)
    }

}