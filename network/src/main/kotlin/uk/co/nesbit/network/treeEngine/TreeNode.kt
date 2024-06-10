package uk.co.nesbit.network.treeEngine

import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.services.KeyServiceImpl
import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.ActorSystem

class TreeNode(private val actorSystem: ActorSystem, networkConfig: NetworkConfiguration) {
    val name: String = networkConfig.networkId.actorName
    val keyService: KeyService = KeyServiceImpl(maxVersion = 1 shl 10)
    val rootNodeActor: ActorRef =
            actorSystem.actorOf(
                    RootNodeActor.getProps(keyService, networkConfig),
                    networkConfig.networkId.actorName
            )
}