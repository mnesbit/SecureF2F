package uk.co.nesbit

import akka.actor.ActorSystem
import uk.co.nesbit.crypto.generateEdDSAKeyPair
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.OverlayAddress
import uk.co.nesbit.network.engine.DnsMockActor
import uk.co.nesbit.network.engine.SimNode
import java.util.*

fun main(args: Array<String>) {
    println("Hello")
    //while(true) {
    val degree = 1
    val N = 2
    val simNetwork = makeRandomNetwork(degree, N)
    val simNodes = mutableListOf<SimNode>()
    val actorSystem = ActorSystem.create("Akka")
    actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
    for (nodeAddress in (1..N)) {
        val networkAddress = NetworkAddress(nodeAddress)
        val links = simNetwork[networkAddress]!!
        val config = NetworkConfiguration(networkAddress, false, links, emptySet())
        simNodes += SimNode(OverlayAddress(generateEdDSAKeyPair().public), actorSystem, config)
    }
//        var stabilised = false
//        var round = 0
//
//        while (!stabilised) {
//            println("-----$round-----")
//            ++round
//            for (node in simNodes) {
//                node.runStateMachine()
//            }
//            simNetwork.shuffleMessages()
//            simNetwork.deliverTillEmpty()
//            for (node in simNodes) {
//                println("---> ${node.address} ${node.routes.size}")
//            }
//            println("message ${simNetwork.messageCount}")
//            stabilised = true
//            for (node in simNodes) {
//                if (node.routes.size != simNodes.size) {
//                    stabilised = false
//                    break
//                }
//            }
//        }
//        println("Done round $round messages ${simNetwork.messageCount}")
    while (System.`in`.read() != 'q'.toInt());
    actorSystem.terminate().value()
    //}

}

private fun makeRandomNetwork(minDegree: Int, N: Int): Map<NetworkAddress, Set<NetworkAddress>> {
    // Note this won't be uniform over regular graphs, but that code gets messy
    val rand = Random()
    val simNetwork = mutableMapOf<NetworkAddress, MutableSet<NetworkAddress>>()

    for (nodeAddress in (1..N)) {
        val currentNode = NetworkAddress(nodeAddress)
        val currentLinks = simNetwork.getOrPut(currentNode) { mutableSetOf() }
        while (currentLinks.size < minDegree) {
            val otherNode = NetworkAddress(1 + rand.nextInt(N))
            if (otherNode != currentNode) {
                currentLinks += otherNode
            }
        }
    }

    return simNetwork
}