package uk.co.nesbit.network.treeEngine

import akka.actor.*
import akka.japi.pf.ReceiveBuilder
import scala.concurrent.duration.Duration
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.PublicAddress
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.PhysicalNetworkActor
import uk.co.nesbit.network.tcpnet.TcpNetworkActor
import uk.co.nesbit.network.util.createProps

class RootNodeActor(val keyService: KeyService, networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(keyService: KeyService, networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, networkConfig)
        }

        private val supervisorStrategy: SupervisorStrategy = OneForOneStrategy(
                -1,
                Duration.Inf()
        ) { _ ->
            SupervisorStrategy.restart() as SupervisorStrategy.Directive?
        }
    }

    override fun supervisorStrategy(): SupervisorStrategy {
        return supervisorStrategy
    }

    private val physicalNetworkActor: ActorRef = if (networkConfig.networkId is PublicAddress) {
        context.actorOf(
                TcpNetworkActor.getProps(networkConfig).withDispatcher("akka.fixed-dispatcher"),
                "net"
        )
    } else {
        context.actorOf(
                PhysicalNetworkActor.getProps(networkConfig).withDispatcher("akka.fixed-dispatcher"),
                "net"
        )
    }

    private val neighbourLinkActor: ActorRef =
            context.actorOf(
                    NeighbourLinkActor.getProps(
                            keyService,
                            networkConfig,
                            physicalNetworkActor
                    ).withDispatcher("akka.fixed-dispatcher"), "neighbours"
            )

    private val hopRoutingActor: ActorRef =
            context.actorOf(
                    HopRoutingActor.getProps(
                            keyService,
                            networkConfig,
                            neighbourLinkActor
                    ).withDispatcher("akka.fixed-dispatcher"), "route"
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