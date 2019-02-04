package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.*
import java.util.concurrent.atomic.AtomicInteger

data class OpenRequest(val remoteNetworkId: NetworkAddress)
data class CloseRequest(val linkId: LinkId)

class PhysicalNetworkActor(private val networkConfig: NetworkConfiguration) : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, networkConfig)
        }

        val linkIdCounter = AtomicInteger(0)
    }

    internal data class ConnectRequest(val sourceNetworkId: NetworkAddress, val linkId: LinkId)
    internal data class ConnectResult(val linkId: LinkId, val opened: Boolean)
    internal data class ConnectionDrop(val initiatorLinkId: LinkId)

    internal val networkId get() = networkConfig.networkId
    internal val owners = mutableSetOf<ActorRef>()

    internal val links = mutableMapOf<LinkId, LinkInfo>()
    internal val targets = mutableMapOf<LinkId, ActorRef>()
    internal val foreignLinks = mutableMapOf<LinkId, LinkId>() // only on passive end
    internal val reverseForeignLinks = mutableMapOf<LinkId, LinkId>() // only on passive end
    internal val addresses = mutableMapOf<Address, LinkId>() // prefers active over passive links

    private val dnsSelector = context.actorSelection("/user/Dns")

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

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(OpenRequest::class.java, ::onOpenRequest)
            .match(CloseRequest::class.java, ::onCloseRequest)
            .match(DnsResponse::class.java, ::onDnsResponse)
            .match(ConnectRequest::class.java, ::onConnectRequest)
            .match(ConnectResult::class.java, ::onConnectResult)
            .match(ConnectionDrop::class.java, ::onConnectionDrop)
            .match(Terminated::class.java, ::onDeath)
            .match(LinkReceivedMessage::class.java, ::onWireMessage)
            .match(LinkSendMessage::class.java, ::onLinkSendMessage)
            .build()

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun createLink(remoteAddress: NetworkAddress): LinkId {
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
            val currentLinkForAddress = addresses[newLinkInfo.route.to]
            if (currentLinkForAddress == null ||
                links[currentLinkForAddress]!!.status < newLinkInfo.status
            ) {
                addresses[newLinkInfo.route.to] = linkId
            }
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
            val reverseForeignLink = reverseForeignLinks.remove(linkId)
            if (reverseForeignLink != null) {
                foreignLinks -= reverseForeignLink
            }
            val currentLinkForAddress = addresses[newLinkInfo.route.to]
            if (currentLinkForAddress == linkId) {
                addresses -= newLinkInfo.route.to
                for (link in links.values) {
                    if (link.status > linkInfo.status && link.route.to == linkInfo.route.to) {
                        addresses[link.route.to] = link.linkId
                        break
                    }
                }
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
        val existingLink = addresses[request.remoteNetworkId]
        if (existingLink != null) {
            val linkInfo = links[existingLink]
            if (linkInfo?.status?.active == true) {
                return
            }
        }
        val newLinkId = createLink(request.remoteNetworkId)
        dnsSelector.tell(DnsLookup(request.remoteNetworkId, newLinkId), self)
    }

    private fun onDnsResponse(dnsResponse: DnsResponse) {
        //log().info("got Dns response $dnsResponse")
        val linkInfo = links[dnsResponse.linkId]!!
        if (dnsResponse.actorRef == null) {
            log().error("Couldn't find Dns for ${linkInfo.route.to}")
        } else {
            if (!linkInfo.status.active) {
                targets[linkInfo.linkId] = dnsResponse.actorRef
                context.watch(dnsResponse.actorRef)
                dnsResponse.actorRef.tell(ConnectRequest(networkId, linkInfo.linkId), self)
            }
        }
    }

    private fun onCloseRequest(request: CloseRequest) {
        //log().info("CloseRequest $request")
        val existingConnection = links[request.linkId] ?: return
        if (existingConnection.status.active) {
            log().info("Closing $existingConnection")
            val target = targets[existingConnection.linkId]
            closeLink(request.linkId)
            target?.tell(ConnectionDrop(existingConnection.linkId), ActorRef.noSender())
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
            log().info("Dropping $existingConnection")
            closeLink(activeLink)
        }
    }

    private fun onDeath(death: Terminated) {
        //log().info("got Terminated $death")
        owners -= death.actor
        val relevantLinks = targets.filter { it.value == death.actor }.map { it.key }
        for (link in relevantLinks) {
            log().info("Dropping ${links[link]}")
            closeLink(link)
        }
    }

    private fun onWireMessage(msg: LinkReceivedMessage) {
        val activeLink = foreignLinks[msg.linkId] ?: msg.linkId
        val renumberedMessage = LinkReceivedMessage(activeLink, msg.msg)
        for (owner in owners) {
            owner.tell(renumberedMessage, self)
        }
    }

    private fun onLinkSendMessage(msg: LinkSendMessage) {
        val target = targets[msg.linkId]
        val activeLink = reverseForeignLinks[msg.linkId] ?: msg.linkId
        val renumberedMessage = LinkReceivedMessage(activeLink, msg.msg)
        target?.tell(renumberedMessage, self)
    }

}