package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.routing.RouteEntry
import uk.co.nesbit.network.api.routing.Routes

class NeighbourLinkActor(
    private val overlayAddress: Address,
    private val networkConfig: NetworkConfiguration,
    val physicalNetworkActor: ActorRef
) :
    AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(
            overlayAddress: Address,
            networkConfig: NetworkConfiguration,
            physicalNetworkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, overlayAddress, networkConfig, physicalNetworkActor)
        }
    }

    private class Start

    private var version = 0
    private val channels = mutableMapOf<LinkId, ActorRef>()
    private val links = mutableMapOf<LinkId, Address>()
    private val neighbours = mutableMapOf<Address, Pair<LinkId, Int>>()
    private var localRoutes: Routes = Routes(VersionedAddress(overlayAddress, 0), emptyList())

    override fun preStart() {
        super.preStart()
        log().info("Starting NeighbourLinkActor")
        self.tell(Start(), ActorRef.noSender())
        physicalNetworkActor.tell(WatchRequest(), self)
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped NeighbourLinkActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart NeighbourLinkActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(Start::class.java) { onStart() }
            .match(LinkInfo::class.java, ::onLinkStatusChange)
            .match(LinkReceivedMessage::class.java, ::onMessage)
            .match(LinkHeartbeat::class.java, ::onLinkHeartbeat)
            .build()

    private fun onStart() {
        val networkSelector = context.actorSelection("../net")
        for (link in networkConfig.staticRoutes) {
            networkSelector.tell(OpenRequest(link), self)
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        log().info(linkInfo.toString())
        if (linkInfo.status.active) {
            val networkService = sender
            val channelProps = SecureChannelActor.getProps(
                linkInfo.linkId,
                overlayAddress,
                linkInfo.status == LinkStatus.LINK_UP_ACTIVE,
                networkService
            )
            val newChannel = context.actorOf(channelProps)
            channels[linkInfo.linkId] = newChannel
            newChannel.tell(VersionUpdate(version), ActorRef.noSender())
        } else {
            val deadAddress = links.remove(linkInfo.linkId)
            if (deadAddress != null) {
                neighbours -= deadAddress
            }
            val deadChannel = channels.remove(linkInfo.linkId)
            if (deadChannel != null) {
                context.stop(deadChannel)
            }
            ++version
            for (channel in channels.values) {
                channel.tell(VersionUpdate(version), ActorRef.noSender())
            }
            recalculateLocalRoutes()
        }
    }

    private fun onMessage(message: LinkReceivedMessage) {
        log().info(message.toString())
        val channel = channels[message.linkId]
        if (channel != null) {
            channel.forward(message, context)
        } else {
            log().info("No channel for $message")
        }
    }

    private fun onLinkHeartbeat(linkHeartbeat: LinkHeartbeat) {
        log().info("onLinkHeartbeat $linkHeartbeat")
        neighbours[linkHeartbeat.remoteAddress.address] =
                Pair(linkHeartbeat.linkId, linkHeartbeat.remoteAddress.version)
        links[linkHeartbeat.linkId] = linkHeartbeat.remoteAddress.address
        recalculateLocalRoutes()
    }

    private fun recalculateLocalRoutes() {
        val outLinks = neighbours.map { RouteEntry(VersionedAddress(it.key, it.value.second)) }
        localRoutes = Routes(VersionedAddress(overlayAddress, version), outLinks)
    }

}