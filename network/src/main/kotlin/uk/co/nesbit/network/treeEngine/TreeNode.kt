package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.ActorSystem
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.engineOld.KeyServiceImpl

class TreeNode(private val actorSystem: ActorSystem, networkConfig: NetworkConfiguration) {
    val keyService: KeyService = KeyServiceImpl(maxVersion = 64)
    val rootNodeActor: ActorRef =
        actorSystem.actorOf(
            RootNodeActor.getProps(keyService, networkConfig),
            networkConfig.networkId.id.toString()
        )
}