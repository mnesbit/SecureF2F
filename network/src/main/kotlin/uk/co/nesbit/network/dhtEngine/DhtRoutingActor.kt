package uk.co.nesbit.network.dhtEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps

class DhtRoutingActor(
    private val keyService: KeyService,
    private val neighbourLinkActor: ActorRef
) :
    AbstractActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            neighbourLinkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, neighbourLinkActor)
        }
    }

    private val owners = mutableSetOf<ActorRef>()
    private var currentNeighbours = emptyList<VersionedIdentity>()

    override fun preStart() {
        super.preStart()
        log().info("Starting DhtRoutingActor")
        neighbourLinkActor.tell(WatchRequest(), self)
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped DhtRoutingActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart DhtRoutingActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(NeighbourUpdate::class.java, ::onNeighbourUpdate)
            .build()

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onNeighbourUpdate(neighbours: NeighbourUpdate) {
        log().info("onNeighbourUpdate $neighbours")
        currentNeighbours = neighbours.addresses
    }
}