package uk.co.nesbit.network.mocknet

import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.simpleactor.*
import java.time.Clock
import java.util.concurrent.atomic.AtomicInteger

class PhysicalNetworkActor(private val networkConfig: NetworkConfiguration) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, networkConfig)
        }

        const val MAX_BUFFER_SIZE = 1000

        val linkIdCounter = AtomicInteger(0)
    }

    internal data class ConnectRequest(val sourceNetworkId: NetworkAddress, val linkId: LinkId)
    internal data class ConnectResult(val linkId: LinkId, val opened: Boolean)
    internal data class ConnectionDrop(val initiatorLinkId: LinkId)
    private class WireMessage(val linkId: LinkId, val seqNo: Int, val ackSeqNo: Int, val msg: ByteArray)
    private class LinkState {
        var seqNo: Int = 0
        var sendAckSeqNo: Int = 0
        var receiveAckSeqNo: Int = 0
    }

    private val networkId: NetworkAddress get() = networkConfig.networkId as NetworkAddress
    private val owners = mutableSetOf<ActorRef>()

    private val links = mutableMapOf<LinkId, LinkInfo>()
    private val targets = mutableMapOf<LinkId, ActorRef>()
    private val foreignLinks = mutableMapOf<LinkId, LinkId>() // only on passive end initiator to local
    private val reverseForeignLinks = mutableMapOf<LinkId, LinkId>() // only on passive end local to initiator

    private val dnsSelector = context.actorSelection("/Dns")
    private val linkBuffers = mutableMapOf<LinkId, LinkState>()
    private var received: Int = 0
    private var written: Int = 0
    private var dropped: Int = 0

    override fun preStart() {
        super.preStart()
        //log().info("Starting PhysicalNetworkActor $networkId")
        dnsSelector.tell(DnsRegistration(networkId), self)
    }

    override fun postStop() {
        for (link in links) {
            if (link.value.status.active) {
                val target = targets[link.key]
                val activeLink = foreignLinks[link.key] ?: link.key
                closeLink(link.key)
                target?.tell(ConnectionDrop(activeLink), ActorRef.noSender())
            }
        }
        super.postStop()
        //log().info("Stopped PhysicalNetworkActor $networkId")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart PhysicalNetworkActor $networkId")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is WatchRequest -> onWatchRequest()
            is OpenRequest -> onOpenRequest(message)
            is CloseRequest -> onCloseRequest(message)
            is DnsResponse -> onDnsResponse(message)
            is ConnectRequest -> onConnectRequest(message)
            is ConnectResult -> onConnectResult(message)
            is ConnectionDrop -> onConnectionDrop(message)
            is Terminated -> onDeath(message)
            is WireMessage -> onWireMessage(message)
            is LinkSendMessage -> onLinkSendMessage(message)
            is CloseAllRequest -> onCloseAll()
        }
    }

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
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
            targets -= linkId
            linkBuffers.remove(linkId)
            val reverseForeignLink = reverseForeignLinks.remove(linkId)
            if (reverseForeignLink != null) {
                foreignLinks -= reverseForeignLink
            }
            if (linkInfo.status != newLinkInfo.status) {
                for (owner in owners) {
                    owner.tell(newLinkInfo, self)
                }
            }
        }
    }

    private fun onOpenRequest(request: OpenRequest) {
        //log().info("OpenRequest $request")
        val newLinkId = createLink(request.remoteNetworkId)
        if (request.remoteNetworkId !is NetworkAddress) {
            for (owner in owners) {
                owner.tell(links[newLinkId]!!, self)
            }
            return
        }
        dnsSelector.tell(DnsLookup(request.remoteNetworkId, newLinkId), self)
    }

    private fun onDnsResponse(dnsResponse: DnsResponse) {
        //log().info("got Dns response $dnsResponse")
        val linkInfo = links[dnsResponse.linkId]!!
        if (dnsResponse.actorRef == null) {
            log().error("Couldn't find Dns for ${linkInfo.route.to}")
            for (owner in owners) {
                owner.tell(linkInfo, self)
            }
        } else {
            targets[linkInfo.linkId] = dnsResponse.actorRef
            context.watch(dnsResponse.actorRef)
            dnsResponse.actorRef.tell(ConnectRequest(networkId, linkInfo.linkId), self)
        }
    }

    private fun onCloseRequest(request: CloseRequest) {
        //log().info("CloseRequest $request ${links[request.linkId]}")
        val existingConnection = links[request.linkId] ?: return
        if (existingConnection.status.active) {
            //log().info("Closing ${request.linkId} $existingConnection")
            val target = targets[request.linkId]
            val closeLinkId = reverseForeignLinks[request.linkId] ?: request.linkId
            closeLink(request.linkId)
            //log().info("drop sent on ${request.linkId} to $closeLinkId ${target}")
            target?.tell(ConnectionDrop(closeLinkId), ActorRef.noSender())
        }
    }

    private fun onConnectRequest(request: ConnectRequest) {
        //log().info("got ConnectRequest $request")
        if (request.sourceNetworkId in networkConfig.blackListedSources) {
            sender.tell(ConnectResult(request.linkId, false), ActorRef.noSender())
        } else {
            sender.tell(ConnectResult(request.linkId, true), ActorRef.noSender())
            val linkId = createLink(request.sourceNetworkId)
            targets[linkId] = sender
            context.watch(sender)
            //log().info("ConnectRequest ${request.linkId}->$linkId")
            foreignLinks[request.linkId] = linkId
            reverseForeignLinks[linkId] = request.linkId
            enableLink(linkId, LinkStatus.LINK_UP_PASSIVE)
        }
    }

    private fun onConnectResult(response: ConnectResult) {
        //log().info("got ConnectResult $response")
        val linkInfo = links[response.linkId]
        if (linkInfo != null) {
            if (response.opened) {
                enableLink(response.linkId, LinkStatus.LINK_UP_ACTIVE)
            }
        }
    }

    private fun onConnectionDrop(drop: ConnectionDrop) {
        //log().info("got ConnectionDrop $drop")
        val activeLink = foreignLinks[drop.initiatorLinkId] ?: drop.initiatorLinkId
        val existingConnection = links[activeLink]
        if (existingConnection != null) {
            //log().info("Dropping ${foreignLinks[drop.initiatorLinkId]} ${drop.initiatorLinkId}")
            closeLink(activeLink)
        }
    }

    private fun onDeath(death: Terminated) {
        //log().info("got Terminated $death")
        owners -= death.actor
        val relevantLinks = targets.filter { it.value == death.actor }.map { it.key }
        for (link in relevantLinks) {
            //log().info("Dropping ${links[link]}")
            closeLink(link)
        }
    }

    private fun onWireMessage(msg: WireMessage) {
        ++received
        val activeLink = foreignLinks[msg.linkId] ?: msg.linkId
        if (links[activeLink]?.status?.active == true) {
            val renumberedMessage =
                LinkReceivedMessage(activeLink, Clock.systemUTC().instant(), msg.msg)
            for (owner in owners) {
                owner.tell(renumberedMessage, self)
            }
            val linkState = linkBuffers.getOrPut(activeLink) { LinkState() }
            linkState.receiveAckSeqNo = msg.ackSeqNo
            linkState.sendAckSeqNo = msg.seqNo
        }
    }

    private fun onLinkSendMessage(msg: LinkSendMessage) {
        val target = targets[msg.linkId] ?: return
        ++written
        val linkState = linkBuffers.getOrPut(msg.linkId) { LinkState() }
        if (linkState.seqNo - linkState.receiveAckSeqNo > MAX_BUFFER_SIZE) {
            ++dropped
            log().warn("dropping packet on ${msg.linkId} due to full buffer $dropped $written $received")
            return
        }
        val seqNo = linkState.seqNo++
        val activeLink = reverseForeignLinks[msg.linkId] ?: msg.linkId
        val renumberedMessage = WireMessage(activeLink, seqNo, linkState.sendAckSeqNo, msg.msg)
        target.tell(renumberedMessage, self)
    }

    private fun onCloseAll() {
        for (linkId in links.keys) {
            onCloseRequest(CloseRequest(linkId))
        }
    }
}