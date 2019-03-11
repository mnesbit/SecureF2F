package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.services.KeyService

class WatchRequest

class RootNodeActor(val keyService: KeyService, val networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(keyService: KeyService, networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, keyService, networkConfig)
        }
    }

    private val physicalNetworkActor: ActorRef =
        context.actorOf(PhysicalNetworkActor.getProps(networkConfig), "net")
    private val neighbourLinkActor: ActorRef =
        context.actorOf(
            NeighbourLinkActor.getProps(
                keyService,
                networkConfig,
                physicalNetworkActor
            ).withDispatcher("akka.fixed-dispatcher"), "neighbours"
        )
    private val routeDiscoveryActor: ActorRef =
        context.actorOf(
            RouteDiscoveryActor.getProps(
                keyService,
                neighbourLinkActor
            ).withDispatcher("akka.fixed-dispatcher"), "routes"
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