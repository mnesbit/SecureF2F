package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.LinkInfo
import uk.co.nesbit.network.api.LinkReceivedMessage
import uk.co.nesbit.network.api.NetworkConfiguration

class NeighbourLinkActor(private val networkConfig: NetworkConfiguration, val physicalNetworkActor: ActorRef) :
    AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration, physicalNetworkActor: ActorRef): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, networkConfig, physicalNetworkActor)
        }
    }

    private class Start

    private val networkSelector = context.actorSelection("../net")

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
            .build()

    private fun onStart() {
        for (link in networkConfig.staticRoutes) {
            networkSelector.tell(OpenRequest(link), self)
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        log().info(linkInfo.toString())
    }

    private fun onMessage(message: LinkReceivedMessage) {
        log().info(message.toString())
    }

}