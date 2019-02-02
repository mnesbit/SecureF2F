package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Cancellable
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.routing.Routes
import uk.co.nesbit.network.api.routing.SignedEntry
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.util.millis

class LocalSendMessage(val networkAddress: SphinxAddress, val msg: ByteArray)
class LocalReceivedMessage(val networkAddress: SphinxAddress, val msg: ByteArray)

class NeighbourLinkActor(
    private val keyService: KeyService,
    private val networkConfig: NetworkConfiguration,
    private val physicalNetworkActor: ActorRef
) :
    AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            networkConfig: NetworkConfiguration,
            physicalNetworkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, keyService, networkConfig, physicalNetworkActor)
        }

        const val LINK_CHECK_INTERVAL_MS = 10000L
    }

    private class CheckStaticLinks

    private val networkAddress: SphinxAddress by lazy {
        val sphinxId = keyService.getVersion(keyService.generateNetworkID(networkConfig.networkId.toString()))
        SphinxAddress(sphinxId.identity)
    }

    private var timer: Cancellable? = null
    private val owners = mutableSetOf<ActorRef>()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val channels = mutableMapOf<LinkId, ActorRef>()
    private val links = mutableMapOf<LinkId, Address>()
    private val addresses = mutableMapOf<Address, LinkId>()
    private val neighbours = mutableMapOf<LinkId, SignedEntry>()

    override fun preStart() {
        super.preStart()
        log().info("Starting NeighbourLinkActor")
        physicalNetworkActor.tell(WatchRequest(), self)
        timer = context.system.scheduler.schedule(
            0L.millis(),
            LINK_CHECK_INTERVAL_MS.millis(),
            self, CheckStaticLinks(),
            context.dispatcher(),
            self
        )
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped NeighbourLinkActor")
        timer?.cancel()
        timer = null
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart NeighbourLinkActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(CheckStaticLinks::class.java) { onCheckStaticLinks() }
            .match(LinkInfo::class.java, ::onLinkStatusChange)
            .match(LinkReceivedMessage::class.java, ::onLinkReceivedMessage)
            .match(SecureChannelClose::class.java, ::onChannelClose)
            .match(SecureChannelRouteUpdate::class.java, ::onRouteUpdate)
            .match(NeighbourReceivedMessage::class.java, ::onNeighbourReceivedMessage)
            .match(LocalSendMessage::class.java, ::onLocalSendMessage)
            .build()

    private fun onWatchRequest() {
        log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onCheckStaticLinks() {
        for (expectedLink in networkConfig.staticRoutes) {
            if (!staticLinkStatus.containsKey(expectedLink)) {
                log().info("open static link to $expectedLink")
                physicalNetworkActor.tell(OpenRequest(expectedLink), self)
            }
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        log().info(linkInfo.toString())
        if (linkInfo.status.active) {
            val networkService = sender
            val channelProps = SecureChannelActor.getProps(
                linkInfo.linkId,
                networkAddress.id,
                linkInfo.status == LinkStatus.LINK_UP_ACTIVE,
                keyService,
                networkService
            )
            val newChannel = context.actorOf(channelProps)
            channels[linkInfo.linkId] = newChannel
            if (linkInfo.route.to in networkConfig.staticRoutes) {
                staticLinkStatus[linkInfo.route.to] = linkInfo.linkId
            }
        } else {
            deleteLinkAddress(linkInfo.linkId)
            neighbours.remove(linkInfo.linkId)
            val deadChannel = channels.remove(linkInfo.linkId)
            if (deadChannel != null) {
                context.stop(deadChannel)
            }
            staticLinkStatus.remove(linkInfo.route.to)
        }
        keyService.incrementAndGetVersion(networkAddress.id)
        recalculateRoutes()
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

    private fun onChannelClose(close: SecureChannelClose) {
        log().info("onChannelClose $close")
        deleteLinkAddress(close.linkId)
        neighbours.remove(close.linkId)
    }

    private fun onRouteUpdate(update: SecureChannelRouteUpdate) {
        log().info("onRouteUpdate $update")
        val address = SphinxAddress(update.routeEntry.routeEntry.to.identity)
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
            Routes.createRoutes(neighbours.values.toList(), keyService, networkAddress.id)
        }
        for (owner in owners) {
            owner.tell(LocalRoutesUpdate(routes), self)
        }
    }


    private fun onLocalSendMessage(msg: LocalSendMessage) {
        log().info("onLocalSendMessage $msg")
        val link = addresses[msg.networkAddress]
        if (link != null) {
            val channel = channels[link]
            if (channel != null) {
                channel.tell(NeighbourSendMessage(link, msg.msg), self)
                return
            }
        }
        log().info("Can't find link for $msg")
    }

    private fun onNeighbourReceivedMessage(msg: NeighbourReceivedMessage) {
        log().info("onNeighbourReceivedMessage $msg")
        val forwardMessage = LocalReceivedMessage(SphinxAddress(msg.sourceId.identity), msg.msg)
        for (owner in owners) {
            owner.tell(forwardMessage, self)
        }
    }
}