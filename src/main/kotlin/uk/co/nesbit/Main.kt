package uk.co.nesbit

import akka.actor.ActorSystem
import akka.pattern.Patterns
import akka.util.Timeout
import com.typesafe.config.ConfigFactory
import scala.concurrent.Await
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.dhtEngine.ClientDhtRequest
import uk.co.nesbit.network.dhtEngine.ClientDhtResponse
import uk.co.nesbit.network.dhtEngine.DhtNode
import uk.co.nesbit.network.dhtEngine.DnsMockActor
import java.lang.Integer.max
import java.time.Duration
import java.util.*
import java.util.concurrent.TimeoutException

fun main(args: Array<String>) {
    println("Hello")
    //while(true) {
    val degree = 5
    val N = 1000
    val simNetwork = makeRandomNetwork(degree, N)
    //val simNetwork = makeLinearNetwork(N)
    println("Network diameter: ${diameter(simNetwork)}")
    val simNodes = mutableListOf<DhtNode>()
    val conf = ConfigFactory.load()
    val actorSystem = ActorSystem.create("Akka", conf)
    actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
    for (nodeAddress in (1..N)) {
        val networkAddress = NetworkAddress(nodeAddress)
        val links = simNetwork[networkAddress]!!
        val config = NetworkConfiguration(networkAddress, false, links, emptySet())
        simNodes += DhtNode(actorSystem, config)
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
//    while (System.`in`.read() != 'q'.toInt());
//    actorSystem.terminate().value()
    //}
    val rand = Random()
    var test = 1
    var requestId = rand.nextLong()
    val timeout = Timeout.create(Duration.ofSeconds(60L))
    var succeeded = 0
    Thread.sleep(20000L)
    while (true) {
        Thread.sleep(1000L)
        val randomNodePut = 1 + rand.nextInt(N)
        val key = SecureHash.secureHash(test.toString())
        println("test $test key $key requestId $requestId")
        val targetPut = actorSystem.actorSelection("akka://Akka/user/$randomNodePut/routing")
        val putRequest = ClientDhtRequest(requestId++, key, test.toString().toByteArray(Charsets.UTF_8))
        val putFut = Patterns.ask(targetPut, putRequest, timeout)
        try {
            val putResponse = Await.result(putFut, timeout.duration()) as ClientDhtResponse
            println("put $randomNodePut ${putResponse.data?.toString(Charsets.UTF_8)}")
        } catch (ex: TimeoutException) {
            println("put $randomNodePut timed out")
        }
        val randomNodeGet = 1 + rand.nextInt(N)
        val targetGet = actorSystem.actorSelection("akka://Akka/user/$randomNodeGet/routing")
        val getRequest = ClientDhtRequest(requestId++, key, null)
        val getFut = Patterns.ask(targetGet, getRequest, timeout)
        try {
            val getResponse = Await.result(getFut, timeout.duration()) as ClientDhtResponse
            if (getResponse.data != null) {
                ++succeeded
            }
            println("get $randomNodeGet ${getResponse.data?.toString(Charsets.UTF_8)}")
        } catch (ex: TimeoutException) {
            println("get $randomNodeGet timed out")
        }
        println("stats $succeeded / $test ${(100.0 * succeeded) / test.toDouble()}")
        ++test
    }
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