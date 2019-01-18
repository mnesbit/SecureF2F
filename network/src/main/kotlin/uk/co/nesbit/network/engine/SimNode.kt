package uk.co.nesbit.network.engine

import akka.actor.ActorSystem
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.OverlayAddress

class SimNode(address: Address, private val actorSystem: ActorSystem, networkConfig: NetworkConfiguration) {
    val rootNodeActor =
        actorSystem.actorOf(RootNodeActor.getProps(address, networkConfig), (address as OverlayAddress).id.toString())
}