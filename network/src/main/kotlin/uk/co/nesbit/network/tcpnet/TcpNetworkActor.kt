package uk.co.nesbit.network.tcpnet

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import akka.io.Tcp
import akka.io.TcpMessage
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.network.mocknet.Congested
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger


class TcpNetworkActor(private val networkConfig: NetworkConfiguration) : UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, networkConfig)
        }

        val linkIdCounter = AtomicInteger(0)
    }

    internal data class ConnectResult(val linkId: LinkId, val linkStatus: LinkStatus)
    internal data class LinkLost(val linkId: LinkId)

    private val networkId: Address get() = networkConfig.networkId
    private val owners = mutableSetOf<ActorRef>()

    private val links = mutableMapOf<LinkId, LinkInfo>()
    private val linkHandlers = mutableMapOf<LinkId, ActorRef>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting TcpNetworkActor")
        val networkAddress = (networkConfig.bindAddress as PublicAddress)
        val bindAddress = InetSocketAddress(networkAddress.host, networkAddress.port)
        val tcpManager: ActorRef = Tcp.get(context.system).manager
        tcpManager.tell(TcpMessage.bind(self, bindAddress, 100), self)
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped TcpNetworkActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart TcpNetworkActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is WatchRequest -> onWatchRequest()
            is OpenRequest -> onOpenRequest(message)
            is CloseRequest -> onCloseRequest(message)
            is CloseAllRequest -> onCloseAll()
            is LinkSendMessage -> onLinkSendMessage(message)
            is LinkReceivedMessage -> onLinkReceivedMessage(message)
            is ConnectResult -> onRequestCompleted(message)
            is LinkLost -> onLinkLost(message)
            is Congested -> onCongested(message)
            is Tcp.Bound -> onServerListening(message)
            is Tcp.CommandFailed -> onFailedCommand(message)
            is Tcp.Connected -> onConnected(message)
            is Terminated -> onDeath(message)
            else -> log().warning("Unrecognised message $message")
        }
    }

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onDeath(death: Terminated) {
        //log().info("got Terminated $death")
        owners -= death.actor
        val relevantLinks = linkHandlers.filter { it.value == death.actor }.map { it.key }
        for (link in relevantLinks) {
            //log().info("Dropping ${links[link]}")
            closeLink(link)
            linkHandlers.remove(link)
        }
    }

    private fun createLink(remoteAddress: Address): LinkId {
        val newLinkId = SimpleLinkId(linkIdCounter.getAndIncrement())
        val newLinkInfo = LinkInfo(newLinkId, Route(networkId, remoteAddress), LinkStatus.LINK_DOWN)
        links[newLinkId] = newLinkInfo
        return newLinkId
    }

    private fun enableLink(linkId: LinkId, newStatus: LinkStatus) {
        val linkInfo = links[linkId]
        if (linkInfo != null) {
            val newLinkInfo = linkInfo.copy(status = newStatus)
            links[linkId] = newLinkInfo
            if (linkInfo.status != newLinkInfo.status) {
                for (owner in owners) {
                    owner.tell(newLinkInfo, self)
                }
            }
        }
    }

    private fun closeLink(linkId: LinkId) {
        val linkInfo = links[linkId]
        if (linkInfo != null) {
            val newLinkInfo = linkInfo.copy(status = LinkStatus.LINK_DOWN)
            links[linkId] = newLinkInfo
            if (linkInfo.status != newLinkInfo.status) {
                for (owner in owners) {
                    owner.tell(newLinkInfo, self)
                }
            }
        }
    }

    private fun onOpenRequest(request: OpenRequest) {
        log().info("OpenRequest $request")
        val linkId = createLink(request.remoteNetworkId)
        if (request.remoteNetworkId !is PublicAddress) {
            val newLinkInfo = links[linkId]!!
            for (owner in owners) {
                owner.tell(newLinkInfo, self)
            }
            return
        }
        val handler = context.actorOf(
                TcpLinkActor.getProps(linkId, request.remoteNetworkId),
                linkId.id.toString()
        )
        context.watch(handler)
        linkHandlers[linkId] = handler
    }

    private fun onCloseRequest(request: CloseRequest) {
        log().info("CloseRequest $request ${links[request.linkId]}")
        val handler = linkHandlers.remove(request.linkId)
        handler?.tell(request, self)
    }

    private fun onCloseAll() {
        log().info("CloseAll Request")
        for (linkId in linkHandlers.keys) {
            onCloseRequest(CloseRequest(linkId))
        }
    }

    private fun onLinkSendMessage(message: LinkSendMessage) {
        val target = linkHandlers[message.linkId]
        target?.tell(message, self)
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        for (owner in owners) {
            owner.tell(message, self)
        }
    }

    private fun onCongested(message: Congested) {
        for (owner in owners) {
            owner.tell(message, self)
        }
    }

    private fun onRequestCompleted(response: ConnectResult) {
        log().info("Client connection result $response")
        val linkInfo = links[response.linkId]
        if (linkInfo != null) {
            if (response.linkStatus.active) {
                enableLink(response.linkId, response.linkStatus)
            } else {
                linkHandlers.remove(response.linkId)
                for (owner in owners) {
                    owner.tell(linkInfo, self)
                }
            }
        }
    }

    private fun onLinkLost(response: LinkLost) {
        log().info("Connection lost $response")
        closeLink(response.linkId)
        linkHandlers.remove(response.linkId)
    }

    private fun onServerListening(message: Tcp.Bound) {
        log().info("Server listening on ${message.localAddress()}")
    }

    private fun onFailedCommand(message: Tcp.CommandFailed) {
        when (message.cmd()) {
            is Tcp.Bind -> {
                log().error("Unable to bind to server port ${networkConfig.bindAddress}")
                context.stop(self)
            }
            else -> log().warning("${message.cmd()} failed with ${message.causedByString()}")
        }
    }

    private fun onConnected(message: Tcp.Connected) {
        log().info("Tcp Inbound Connected $message")
        val remoteAddress = PublicAddress(message.remoteAddress().hostString, message.remoteAddress().port)
        val newLink = createLink(remoteAddress)
        val handler = context.actorOf(
                TcpLinkActor.getProps(newLink, null),
                newLink.id.toString()
        )
        context.watch(handler)
        linkHandlers[newLink] = handler
        handler.forward(message, context)
    }

}