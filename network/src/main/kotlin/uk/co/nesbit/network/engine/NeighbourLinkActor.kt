package uk.co.nesbit.network.engine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.routing.Routes
import uk.co.nesbit.network.api.routing.SignedEntry
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.OpenRequest
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis

class NeighbourSendMessage(val networkAddress: SphinxPublicIdentity, val msg: ByteArray)
class NeighbourReceivedMessage(val networkAddress: SphinxPublicIdentity, val msg: ByteArray)

class NeighbourLinkActor(
    private val keyService: KeyService,
    private val networkConfig: NetworkConfiguration,
    private val physicalNetworkActor: ActorRef
) :
    AbstractActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            networkConfig: NetworkConfiguration,
            physicalNetworkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, networkConfig, physicalNetworkActor)
        }

        const val LINK_CHECK_INTERVAL_MS = 10000L
    }

    private class CheckStaticLinks

    private val networkAddress: SphinxPublicIdentity by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val sphinxId = keyService.getVersion(keyService.generateNetworkID(networkConfig.networkId.toString()))
        sphinxId.identity
    }

    private val owners = mutableSetOf<ActorRef>()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val channels = mutableMapOf<LinkId, ActorRef>()
    private val links = mutableMapOf<LinkId, SphinxPublicIdentity>()
    private val addresses = mutableMapOf<SphinxPublicIdentity, LinkId>()
    private val neighbours = mutableMapOf<LinkId, SignedEntry>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting NeighbourLinkActor")
        physicalNetworkActor.tell(WatchRequest(), self)
        timers.startTimerAtFixedRate(
            "staticLinkPoller",
            CheckStaticLinks(),
            LINK_CHECK_INTERVAL_MS.millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped NeighbourLinkActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart NeighbourLinkActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(CheckStaticLinks::class.java) { onCheckStaticLinks() }
            .match(LinkInfo::class.java, ::onLinkStatusChange)
            .match(LinkReceivedMessage::class.java, ::onLinkReceivedMessage)
            .match(SecureChannelClose::class.java, ::onSecureChannelClose)
            .match(SecureChannelRouteUpdate::class.java, ::onSecureChannelRouteUpdate)
            .match(SecureChannelReceivedMessage::class.java, ::onSecureChannelReceivedMessage)
            .match(NeighbourSendMessage::class.java, ::onNeigbourSendMessage)
            .build()

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onCheckStaticLinks() {
        for (expectedLink in networkConfig.staticRoutes) {
            if (!staticLinkStatus.containsKey(expectedLink)) {
                //log().info("open static link to $expectedLink")
                physicalNetworkActor.tell(OpenRequest(expectedLink), self)
            }
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        //log().info("onLinkStatusChange $linkInfo")
        if (linkInfo.status.active) {
            val networkService = sender
            val channelProps = SecureChannelActor.getProps(
                linkInfo.linkId,
                networkAddress.id,
                linkInfo.status == LinkStatus.LINK_UP_ACTIVE,
                keyService,
                networkService
            )
            val newChannel = context.actorOf(channelProps.withDispatcher("akka.fixed-dispatcher"))
            channels[linkInfo.linkId] = newChannel
            if (linkInfo.route.to in networkConfig.staticRoutes) {
                staticLinkStatus[linkInfo.route.to] = linkInfo.linkId
            }
        } else {
            val deadChannel = channels.remove(linkInfo.linkId)
            if (deadChannel != null) {
                context.stop(deadChannel)
            }
            staticLinkStatus.remove(linkInfo.route.to)
            keyService.incrementAndGetVersion(networkAddress.id)
            neighbours.clear()
            links.clear()
            addresses.clear()
            recalculateRoutes()
        }
    }

    private fun deleteLinkAddress(linkId: LinkId) {
        val address = links.remove(linkId)
        if (address != null && addresses[address] == linkId) {
            addresses.remove(address)
            for (link in links) {
                if (link.value == address) {
                    addresses[address] = link.key
                    break
                }
            }
        }
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        val channel = channels[message.linkId]
        if (channel != null) {
            channel.forward(message, context)
        } else {
            log().info("No channel for $message")
        }
    }

    private fun onSecureChannelClose(close: SecureChannelClose) {
        //log().info("onSecureChannelClose $close")
        deleteLinkAddress(close.linkId)
        neighbours.remove(close.linkId)
    }

    private fun onSecureChannelRouteUpdate(update: SecureChannelRouteUpdate) {
        val currentIdentity = keyService.getVersion(networkAddress.id)
        if (currentIdentity != update.fromId) { // old version, so discard
            return
        }
        //log().info("onSecureChannelRouteUpdate $update")
        val address = update.routeEntry.routeEntry.to.identity
        links[update.linkId] = address
        if (!addresses.containsKey(address)) {
            addresses[address] = update.linkId
        }
        neighbours[update.linkId] = update.routeEntry
        recalculateRoutes()
    }

    private fun recalculateRoutes() {
        val routes = if (neighbours.isEmpty()) {
            null
        } else {
            val entries = addresses.values.mapNotNull { neighbours[it] }
            Routes.createRoutes(entries, keyService, networkAddress.id)
        }
        for (owner in owners) {
            owner.tell(LocalRoutesUpdate(networkAddress, routes), self)
        }
    }


    private fun onNeigbourSendMessage(msg: NeighbourSendMessage) {
        //log().info("onNeigbourSendMessage $msg")
        val link = addresses[msg.networkAddress]
        if (link != null) {
            val channel = channels[link]
            if (channel != null) {
                channel.tell(SecureChannelSendMessage(link, msg.msg), self)
                return
            }
        }
        log().info("Can't find link for $msg")
    }

    private fun onSecureChannelReceivedMessage(msg: SecureChannelReceivedMessage) {
        //log().info("onSecureChannelReceivedMessage $msg")
        val forwardMessage = NeighbourReceivedMessage(msg.sourceId.identity, msg.msg)
        for (owner in owners) {
            owner.tell(forwardMessage, self)
        }
    }
}