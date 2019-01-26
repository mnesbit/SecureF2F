package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkConfiguration

class RootNodeActor(val layer1Address: Address, networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(overlayAddress: Address, networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, overlayAddress, networkConfig)
        }
    }

    private val physicalNetworkActor: ActorRef =
        context.actorOf(PhysicalNetworkActor.getProps(networkConfig), "net")
    private val neighbourLinkActor: ActorRef =
        context.actorOf(NeighbourLinkActor.getProps(layer1Address, networkConfig, physicalNetworkActor), "neighbours")

    override fun preStart() {
        super.preStart()
        log().info("Starting RootNodeActor $layer1Address")
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped RootNodeActor $layer1Address")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart RootNodeActor $layer1Address")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(String::class.java, ::onMessage)
            .build()

    private fun onMessage(message: String) {
        log().info(message)
    }
}