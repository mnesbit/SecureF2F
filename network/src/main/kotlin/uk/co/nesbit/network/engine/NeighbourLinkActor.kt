package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.services.KeyService

class NeighbourLinkActor(
    private val keyService: KeyService,
    private val networkConfig: NetworkConfiguration,
    val physicalNetworkActor: ActorRef
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
    }

    val networkAddress: SphinxAddress by lazy {
        val sphinxId = keyService.getVersion(keyService.generateNetworkID(networkConfig.networkId.toString()))
        SphinxAddress(sphinxId.identity)
    }

    private class Start

    private val channels = mutableMapOf<LinkId, ActorRef>()
    private val links = mutableMapOf<LinkId, Address>()
//    private val neighbours = mutableMapOf<Address, Pair<LinkId, Int>>()
//    private var localRoutes: Routes = Routes.createRoutes()

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
            .match(SecureChannelClose::class.java, ::onChannelClose)
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
                networkAddress.id,
                linkInfo.status == LinkStatus.LINK_UP_ACTIVE,
                keyService,
                networkService
            )
            val newChannel = context.actorOf(channelProps)
            channels[linkInfo.linkId] = newChannel
        } else {
            val deadAddress = links.remove(linkInfo.linkId)
//            if (deadAddress != null) {
//                neighbours -= deadAddress
//            }
            val deadChannel = channels.remove(linkInfo.linkId)
            if (deadChannel != null) {
                context.stop(deadChannel)
            }
            keyService.incrementAndGetVersion(networkAddress.id)
//            ++version
//            for (channel in channels.values) {
//                channel.tell(VersionUpdate(version), ActorRef.noSender())
//            }
//            recalculateLocalRoutes()
        }
    }

    private fun onMessage(message: LinkReceivedMessage) {
        val channel = channels[message.linkId]
        if (channel != null) {
            channel.forward(message, context)
        } else {
            log().info("No channel for $message")
        }
    }

    private fun onChannelClose(close: SecureChannelClose) {
        log().info("onChannelClose $close")
    }
//
//    private fun onLinkHeartbeat(linkHeartbeat: LinkHeartbeat) {
//        log().info("onLinkHeartbeat $linkHeartbeat")
//        neighbours[linkHeartbeat.remoteAddress.address] =
//                Pair(linkHeartbeat.linkId, linkHeartbeat.remoteAddress.version)
//        links[linkHeartbeat.linkId] = linkHeartbeat.remoteAddress.address
//        recalculateLocalRoutes()
//    }
//
//    private fun recalculateLocalRoutes() {
//        val outLinks = neighbours.map { RouteEntry(VersionedAddress(it.key, it.value.second)) }
//        localRoutes = Routes(VersionedAddress(layer1Address, version), outLinks)
//    }
//
}