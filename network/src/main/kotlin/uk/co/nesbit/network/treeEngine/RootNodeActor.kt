package uk.co.nesbit.network.treeEngine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.PhysicalNetworkActor2
import uk.co.nesbit.network.util.createProps

class RootNodeActor(val keyService: KeyService, networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(keyService: KeyService, networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, networkConfig)
        }
    }

    private val physicalNetworkActor: ActorRef =
        context.actorOf(
            PhysicalNetworkActor2.getProps(networkConfig).withDispatcher("akka.fixed-dispatcher"), "net"
        )

    private val neighbourLinkActor: ActorRef =
        context.actorOf(
            NeighbourLinkActor.getProps(
                keyService,
                networkConfig,
                physicalNetworkActor
            ).withDispatcher("akka.fixed-dispatcher"), "neighbours"
        )

    override fun preStart() {
        super.preStart()
        //log().info("Starting RootNodeActor ${networkConfig.networkId}")
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped RootNodeActor ${networkConfig.networkId}")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart RootNodeActor ${networkConfig.networkId}")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(String::class.java, ::onMessage)
            .build()

    private fun onMessage(message: String) {
        log().info(message)
    }
}