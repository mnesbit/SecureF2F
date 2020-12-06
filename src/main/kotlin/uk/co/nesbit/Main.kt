package uk.co.nesbit

import akka.actor.ActorRef
import akka.actor.ActorSystem
import akka.pattern.Patterns.ask
import akka.stream.OverflowStrategy
import akka.stream.javadsl.Sink
import akka.stream.javadsl.Source
import akka.util.Timeout
import com.typesafe.config.ConfigFactory
import scala.concurrent.Await
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.active
import uk.co.nesbit.network.mocknet.DnsMockActor
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.treeEngine.*
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
    //val simNetwork = convertToHTTPNetwork(makeLinearNetwork(2))
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
    //pollDht(simNodes, actorSystem)
    createStream(simNodes, actorSystem)
    //actorSystem.terminate().value()
}

private fun createStream(
    simNodes: MutableList<TreeNode>,
    actorSystem: ActorSystem
) {
    val random = Random()
    val timeout = Timeout.create(Duration.ofSeconds(120L))
    var sourceName: String
    var sourceAddress: SecureHash? = null
    var destName: String
    var destAddress: SecureHash? = null
    while (true) {
        Thread.sleep(1000L)
        sourceName = simNodes[random.nextInt(simNodes.size)].name
        val randomSourceNode = actorSystem.actorSelection("akka://Akka/user/$sourceName/session")
        val sourceFut = ask(randomSourceNode, SelfAddressRequest(), timeout)
        try {
            val sourceResult = Await.result(sourceFut, timeout.duration()) as SelfAddressResponse
            sourceAddress = sourceResult.address
        } catch (ex: TimeoutException) {
        }
        if (sourceAddress == null) {
            continue
        }
        destName = simNodes[random.nextInt(simNodes.size)].name
        val randomDestNode = actorSystem.actorSelection("akka://Akka/user/$destName/session")
        val destFut = ask(randomDestNode, SelfAddressRequest(), timeout)
        try {
            val destResult = Await.result(destFut, timeout.duration()) as SelfAddressResponse
            destAddress = destResult.address
        } catch (ex: TimeoutException) {
        }
        if (destAddress == null) {
            continue
        }
        break
    }
    println("using $sourceName $sourceAddress -> $destName $destAddress")
    val destSourcePair = Source.actorRef<Any>(
        { elem -> Optional.empty() },
        { elem -> Optional.empty() },
        10,
        OverflowStrategy.dropHead()
    ).preMaterialize(actorSystem)
    val printerRef = destSourcePair.first()
    val destSource = destSourcePair.second()
    val destNodeSel = actorSystem.actorSelection("akka://Akka/user/$destName/session")
    destSource.to(Sink.foreach { msg ->
        if (msg is SessionStatusInfo) {
            println("New session $msg")
            destNodeSel.tell(RemoteConnectionAcknowledge(msg.sessionId, 999, true), printerRef)
        } else if (msg is ReceiveSessionData) {
            println("Received ${msg.payload.toString(Charsets.UTF_8)} from ${msg.sessionId}")
        } else {
            println("unknown message type $msg")
        }
    }).run(actorSystem)
    destNodeSel.tell(WatchRequest(), printerRef)
    var queryNo = 0
    var sessionId: Long
    while (true) {
        Thread.sleep(1000L)
        val sessionSourceNode = actorSystem.actorSelection("akka://Akka/user/$sourceName/session")
        println("Send open query")
        val openFut = ask(sessionSourceNode, OpenSessionRequest(queryNo++, destAddress!!), timeout)
        try {
            val destResult = Await.result(openFut, timeout.duration()) as SessionStatusInfo
            println("result $destResult ${destResult.sessionId}")
            if (destResult.status.active) {
                sessionId = destResult.sessionId
                break
            }
        } catch (ex: TimeoutException) {
        }
    }
    println("Session $sessionId opened")

    var packetNo = 0
    while (packetNo < 2000) {
        val sessionSourceNode = actorSystem.actorSelection("akka://Akka/user/$sourceName/session")
        println("Send data query $packetNo")
        val sendFut = ask(
            sessionSourceNode,
            SendSessionData(sessionId, "hello$packetNo".toByteArray(Charsets.UTF_8)),
            timeout
        )
        try {
            val destResult = Await.result(sendFut, timeout.duration()) as SendSessionDataAck
            println("result $destResult ${destResult.sessionId} ${destResult.success}")
            if (destResult.success) {
                packetNo++
            } else {
                Thread.sleep(100L)
            }
        } catch (ex: TimeoutException) {
        }
    }
    val sessionNode = actorSystem.actorSelection("akka://Akka/user/$sourceName/session")
    sessionNode.tell(CloseSessionRequest(null, sessionId, null), ActorRef.noSender())
    while (true) {
        Thread.sleep(1000L)
    }
}

private fun pollDht(
    simNodes: MutableList<TreeNode>,
    actorSystem: ActorSystem
) {
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

private fun convertToHTTPNetwork(simNetwork: Map<Address, Set<Address>>): Map<Address, Set<Address>> {
    val httpNetwork = mutableMapOf<Address, Set<Address>>()
    for (networkAddress in simNetwork.keys) {
        val httpAddress: Address = (networkAddress as NetworkAddress).toLocalHTTPAddress()
        val links = simNetwork[networkAddress]!!
        val httpLinks: Set<Address> = links.map { (it as NetworkAddress).toLocalHTTPAddress() }.toSet()
        httpNetwork[httpAddress] = httpLinks
    }
    return httpNetwork
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