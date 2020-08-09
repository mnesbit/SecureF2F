package uk.co.nesbit

import akka.actor.ActorSystem
import akka.pattern.Patterns.ask
import akka.util.Timeout
import com.typesafe.config.ConfigFactory
import scala.concurrent.Await
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.mocknet.DnsMockActor
import uk.co.nesbit.network.treeEngine.ClientDhtRequest
import uk.co.nesbit.network.treeEngine.ClientDhtResponse
import uk.co.nesbit.network.treeEngine.TreeNode
import uk.co.nesbit.utils.resourceAsString
import java.lang.Integer.max
import java.time.Duration
import java.util.*
import java.util.concurrent.TimeoutException


fun main(args: Array<String>) {
    println("Hello")
    //while(true) {
    val degree = 3
    val N = 1000
    val simNetwork = convertToTcpNetwork(makeRandomNetwork(degree, N))
    //val simNetwork = convertToTcpNetwork(makeLinearNetwork(2))
    //val simNetwork = makeASNetwork()
    //println("Network diameter: ${diameter(simNetwork)}")
    val simNodes = mutableListOf<TreeNode>()
    val conf = ConfigFactory.load()
    val actorSystem = ActorSystem.create("Akka", conf)
    actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
    for (networkAddress in simNetwork.keys) {
        val links = simNetwork[networkAddress]!!
        val config = NetworkConfiguration(networkAddress, networkAddress, false, links, emptySet())
        simNodes += TreeNode(actorSystem, config)
    }
//    val num = Scanner(System.`in`).nextInt()
//    val ref = actorSystem.actorSelection("akka://Akka/user/$num/neighbours")
//    ref.tell(Nuke(), ActorRef.noSender())
//    while (System.`in`.read() != 'q'.toInt());
    val random = Random()
    var round = 0
    val timeout = Timeout.create(Duration.ofSeconds(120L))
    while (true) {
        Thread.sleep(5000L)
        ++round
        val putTarget = simNodes[random.nextInt(simNodes.size)].name
        val randomPutNode = actorSystem.actorSelection("akka://Akka/user/$putTarget/route")
        val data = round.toByteArray()
        val key = SecureHash.secureHash(data)
        val putRequest = ClientDhtRequest(key, data)
        println("send put $round $key to ${randomPutNode.pathString()}")
        val startPut = System.nanoTime()
        val putFut = ask(randomPutNode, putRequest, timeout)
        try {
            val putResult = Await.result(putFut, timeout.duration()) as ClientDhtResponse
            val diff = ((System.nanoTime() - startPut) / 1000L).toDouble() / 1000.0
            println("put result $putResult in $diff ms")
        } catch (ex: TimeoutException) {
            println("put query $round timed out")
        }

        val getTarget = simNodes[random.nextInt(simNodes.size)].name
        val randomGetNode = actorSystem.actorSelection("akka://Akka/user/$getTarget/route")
        val getRequest = ClientDhtRequest(key, null)
        println("send get $round $key to ${randomGetNode.pathString()}")
        val startGet = System.nanoTime()
        val getFut = ask(randomGetNode, getRequest, timeout)
        try {
            val getResult = Await.result(getFut, timeout.duration()) as ClientDhtResponse
            val diff = ((System.nanoTime() - startGet) / 1000L).toDouble() / 1000.0
            println("get result $getResult in $diff ms")
        } catch (ex: TimeoutException) {
            println("get query $round timed out")
        }
    }
    actorSystem.terminate().value()
}

private fun convertToTcpNetwork(simNetwork: Map<Address, Set<Address>>): Map<Address, Set<Address>> {
    val tcpNetwork = mutableMapOf<Address, Set<Address>>()
    for (networkAddress in simNetwork.keys) {
        val tcpAddress: Address = (networkAddress as NetworkAddress).toLocalPublicAddress()
        val links = simNetwork[networkAddress]!!
        val tcpLinks: Set<Address> = links.map { (it as NetworkAddress).toLocalPublicAddress() }.toSet()
        tcpNetwork[tcpAddress] = tcpLinks
    }
    return tcpNetwork
}

private fun diameter(graph: Map<Address, Set<Address>>): Pair<Int, Int> {
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

private fun makeLinearNetwork(N: Int): MutableMap<Address, Set<Address>> {
    val simNetwork = mutableMapOf<Address, Set<Address>>()
    for (i in (1..N)) {
        val links = mutableSetOf<Address>()
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

private fun makeRandomNetwork(minDegree: Int, N: Int): Map<Address, Set<Address>> {
    // Note this won't be uniform over regular graphs, but that code gets messy
    val rand = Random()
    val simNetwork = mutableMapOf<Address, MutableSet<Address>>()

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

private fun makeASNetwork(): Map<Address, Set<Address>> {
    val classLoader = ClassLoader.getSystemClassLoader()
    //From https://snap.stanford.edu/data/as-733.html
    val networkInfoFile = resourceAsString("./as20000102.txt", classLoader)!!
    val lines = networkInfoFile.lines()
    val network = mutableMapOf<Address, MutableSet<Address>>()
    for (line in lines) {
        if (line.startsWith('#')) continue
        val splits = line.split(' ', ',', '\t')
        if (splits.size < 2) continue
        val left = splits[0].toInt()
        val right = splits[1].toInt()
        if (left == right) continue
        val leftNode = NetworkAddress(left)
        val rightNode = NetworkAddress(right)
        val linksLeft = network.getOrPut(leftNode) { mutableSetOf() }
        linksLeft += rightNode
        val linksRight = network.getOrPut(rightNode) { mutableSetOf() }
        linksRight += leftNode
    }
    return network
}