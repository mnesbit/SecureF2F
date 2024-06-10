package uk.co.nesbit.network.mocknet

import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.simpleactor.*

data class DnsRegistration(val networkId: NetworkAddress)
data class DnsLookup(val networkId: NetworkAddress, val linkId: LinkId)
data class DnsResponse(val linkId: LinkId, val actorRef: ActorRef?)

class DnsMockActor : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass)
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

    override fun onReceive(message: Any) {
        when (message) {
            is DnsRegistration -> onRegistration(message)
            is Terminated -> onDeath(message)
            is DnsLookup -> onLookup(message)
            else -> throw UnhandledMessage("Not handled message type ${message.javaClass.name}")
        }
    }

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