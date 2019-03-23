package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.NetworkAddress

data class DnsRegistration(val networkId: NetworkAddress)
data class DnsLookup(val networkId: NetworkAddress, val linkId: LinkId)
data class DnsResponse(val linkId: LinkId, val actorRef: ActorRef?)

class DnsMockActor : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass)
        }
    }

    private val knownAddresses = mutableMapOf<NetworkAddress, ActorRef>()
    private val knownActors = mutableMapOf<ActorRef, NetworkAddress>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting DnsMockActor")
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped DnsMockActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart DnsMockActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(DnsRegistration::class.java, ::onRegistration)
            .match(Terminated::class.java, ::onDeath)
            .match(DnsLookup::class.java, ::onLookup)
            .build()

    private fun onRegistration(registration: DnsRegistration) {
        //log().info("Received DNS registration $registration")
        knownAddresses[registration.networkId] = sender
        knownActors[sender] = registration.networkId
        context.watch(sender)
    }

    private fun onDeath(death: Terminated) {
        //log().info("Received Death of watched actor $death")
        val address = knownActors.remove(death.actor)
        if (address != null) {
            knownAddresses -= address
        }
    }

    private fun onLookup(lookup: DnsLookup) {
        //log().info("Received DNS request $lookup")
        val node = knownAddresses[lookup.networkId]
        sender.tell(DnsResponse(lookup.linkId, node), self)
    }
}