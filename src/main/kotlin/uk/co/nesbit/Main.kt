package uk.co.nesbit

import akka.actor.ActorSystem
import com.typesafe.config.ConfigFactory
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.engine.DnsMockActor
import uk.co.nesbit.network.engine.SimNode
import java.util.*

fun main(args: Array<String>) {
    println("Hello")
    //while(true) {
    val degree = 5
    val N = 1000
    val simNetwork = makeRandomNetwork(degree, N)
    //val simNetwork = makeLinearNetwork(N)
    val simNodes = mutableListOf<SimNode>()
    val conf = ConfigFactory.load()
    val actorSystem = ActorSystem.create("Akka", conf)
    actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
    for (nodeAddress in (1..N)) {
        val networkAddress = NetworkAddress(nodeAddress)
        val links = simNetwork[networkAddress]!!
        val config = NetworkConfiguration(networkAddress, false, links, emptySet())
        simNodes += SimNode(actorSystem, config)
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

private fun makeLinearNetwork(N: Int): MutableMap<NetworkAddress, Set<NetworkAddress>> {
    val simNetwork = mutableMapOf<NetworkAddress, Set<NetworkAddress>>()
    for (i in (1..N)) {
        val links = mutableSetOf<NetworkAddress>()
        if (i > 1) {
            links += NetworkAddress(i - 1)
        }
        if (i < N) {
            links += NetworkAddress(i + 1)
        }
        simNetwork[NetworkAddress(i)] = links
    }
    return simNetwork
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
                val otherLinks = simNetwork.getOrPut(otherNode) { mutableSetOf() }
                currentLinks += otherNode
                otherLinks += currentNode
            }
        }
    }

    return simNetwork
}