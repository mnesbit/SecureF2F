package uk.co.nesbit.network.engine

import akka.actor.ActorRef
import akka.actor.ActorSystem
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.engineOld.KeyServiceImpl

class SimNode(private val actorSystem: ActorSystem, networkConfig: NetworkConfiguration) {
    val keyService: KeyService = KeyServiceImpl(maxVersion = 64, minVersion = 0)
    val rootNodeActor: ActorRef =
        actorSystem.actorOf(
            RootNodeActor.getProps(keyService, networkConfig),
            networkConfig.networkId.id.toString()
        )
}