package uk.co.nesbit

import akka.actor.ActorSystem
import com.typesafe.config.ConfigFactory
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.mocknet.DnsMockActor
import uk.co.nesbit.network.treeEngine.TreeNode
import java.lang.Integer.max
import java.util.*

fun main(args: Array<String>) {
    println("Hello")
    //while(true) {
    val degree = 5
    val N = 10000
    val simNetwork = makeRandomNetwork(degree, N)
    //val simNetwork = makeLinearNetwork(N)
    //println("Network diameter: ${diameter(simNetwork)}")
    val simNodes = mutableListOf<TreeNode>()
    val conf = ConfigFactory.load()
    val actorSystem = ActorSystem.create("Akka", conf)
    actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
    for (nodeAddress in (1..N)) {
        val networkAddress = NetworkAddress(nodeAddress)
        val links = simNetwork[networkAddress]!!
        val config = NetworkConfiguration(networkAddress, false, links, emptySet())
        simNodes += TreeNode(actorSystem, config)
    }
    while (System.`in`.read() != 'q'.toInt());
    actorSystem.terminate().value()
}

private fun diameter(graph: Map<NetworkAddress, Set<NetworkAddress>>): Pair<Int, Int> {
    val INF = 1000000
    val allDistances = Array(graph.size) { IntArray(graph.size) { INF } }
    val idMap = graph.keys.mapIndexed { index, networkAddress -> networkAddress to index }.toMap()
    for (links in graph) {
        val i = idMap[links.key]!!
        for (link in links.value) {
            val j = idMap[link]!!
            allDistances[i][j] = 1
        }
    }
    for (i in 0 until graph.size) {
        for (j in 0 until graph.size) {
            for (k in 0 until graph.size) {
                if (allDistances[i][k] + allDistances[k][j] < allDistances[i][j]) {
                    allDistances[i][j] = allDistances[i][k] + allDistances[k][j]
                }
            }
        }
    }
    var diameter = 0
    var distTotal = 0
    var linkCount = 0
    for (i in 0 until graph.size) {
        for (j in 0 until graph.size) {
            val dist = allDistances[i][j]
            if (dist < INF) {
                diameter = max(dist, diameter)
                distTotal += dist
                ++linkCount
            }
        }
    }
    return Pair(diameter, (distTotal / linkCount))
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