package uk.co.nesbit.network.engine

import akka.actor.ActorRef
import akka.actor.ActorSystem
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkConfiguration

class SimNode(address: Address, private val actorSystem: ActorSystem, networkConfig: NetworkConfiguration) {
    val rootNodeActor: ActorRef =
        actorSystem.actorOf(
            RootNodeActor.getProps(address, networkConfig),
            networkConfig.networkId.id.toString()
        )
}