package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkConfiguration

class RootNodeActor(val overlayAddress: Address, networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(overlayAddress: Address, networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, overlayAddress, networkConfig)
        }
    }

    val physicalNetworkActor =
        context.actorOf(PhysicalNetworkActor.getProps(networkConfig), networkConfig.networkId.id.toString())
    val neighbourLinkActor = context.actorOf(NeighbourLinkActor.getProps(physicalNetworkActor), "neighbours")

    override fun preStart() {
        super.preStart()
        log().info("Starting Node Actor")
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped Node Actor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart Node Actor")
    }

    override fun createReceive() =
        ReceiveBuilder()
            .match(String::class.java, this::onMessage)
            .build()

    private fun onMessage(message: String) {
        log().info(message)
    }
}