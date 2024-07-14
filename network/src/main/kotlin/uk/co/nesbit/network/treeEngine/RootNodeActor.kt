package uk.co.nesbit.network.treeEngine

import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.PublicAddress
import uk.co.nesbit.network.api.URLAddress
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.PhysicalNetworkActor
import uk.co.nesbit.network.tcpnet.HttpsNetworkActor
import uk.co.nesbit.network.tcpnet.TcpNetworkActor
import uk.co.nesbit.simpleactor.*

class RootNodeActor(val keyService: KeyService, networkConfig: NetworkConfiguration) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(keyService: KeyService, networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, networkConfig)
        }
    }

    override fun supervisorStrategy(
        context: ActorContext,
        child: ActorRef,
        cause: Throwable,
        retryCounts: Map<String, Int>
    ): SupervisorResponse {
        return SupervisorResponse.RestartChild
    }

    private val physicalNetworkActor: ActorRef = when (networkConfig.networkId) {
        is PublicAddress -> {
            context.actorOf(
                TcpNetworkActor.getProps(networkConfig),
                "net"
            )
        }
        is URLAddress -> {
            context.actorOf(
                HttpsNetworkActor.getProps(networkConfig, keyService),
                "net"
            )
        }
        else -> {
            context.actorOf(
                PhysicalNetworkActor.getProps(networkConfig),
                "net"
            )
        }
    }

    private val neighbourLinkActor: ActorRef =
        context.actorOf(
            NeighbourLinkActor.getProps(
                keyService,
                networkConfig,
                physicalNetworkActor
            ), "neighbours"
        )

    private val hopRoutingActor: ActorRef =
        context.actorOf(
            HopRoutingActor.getProps(
                keyService,
                neighbourLinkActor
            ), "route"
        )

    @Suppress("UNUSED")
    private val sessionActor: ActorRef =
        context.actorOf(
            SessionActor.getProps(
                keyService,
                hopRoutingActor
            ), "session"
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

    override fun onReceive(message: Any) {
        when (message) {
            is String -> onMessage(message)
            else -> throw UnhandledMessage("Unhandled message ${message.javaClass.name}")
        }
    }

    private fun onMessage(message: String) {
        log().info(message)
    }
}