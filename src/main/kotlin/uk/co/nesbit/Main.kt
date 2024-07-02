package uk.co.nesbit

import com.typesafe.config.ConfigFactory
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.mocknet.DnsMockActor
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.treeEngine.*
import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.ActorSystem
import uk.co.nesbit.simpleactor.ask
import uk.co.nesbit.utils.resourceAsString
import java.lang.Integer.max
import java.time.Duration
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException


fun main() {
    println("Hello")
    //while(true) {
    val degree = 3
    val N = 1000
    //val simNetwork = makeRandomNetwork(degree, N)
    val simNetwork = convertToTcpNetwork(makeRandomNetwork(degree, N))
    //val simNetwork = convertToTcpNetwork(makeBarabasiAlbertNetwork(degree, N))
    //val simNetwork = convertToTcpNetwork(makeLinearNetwork(2))
    //val simNetwork = convertToHTTPNetwork(makeLinearNetwork(2))
    //val simNetwork = makeASNetwork()
    //println("Network diameter: ${diameter(simNetwork)}")
    val simNodes = mutableListOf<TreeNode>()
    val conf = ConfigFactory.load()
    val actorSystem = ActorSystem.create("p2p", conf)
    actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
    for (networkAddress in simNetwork.keys) {
        val links = simNetwork[networkAddress]!!
        val config = NetworkConfiguration(networkAddress, networkAddress, false, links, emptySet())
        simNodes += TreeNode(actorSystem, config)
    }
    pollDht(simNodes, actorSystem)
    createStream(simNodes, actorSystem)
    actorSystem.stop()
    println("bye")
}

private fun createStream(
    simNodes: MutableList<TreeNode>,
    actorSystem: ActorSystem
) {
    val random = Random()
    val timeout = Duration.ofSeconds(120L)
    var sourceAddress: SecureHash? = null
    var destAddress: SecureHash? = null
    val sourceName: String = simNodes[random.nextInt(simNodes.size)].name
    val randomSourceNodes = actorSystem.actorSelection("SimpleActor://p2p/$sourceName/session")
    while (randomSourceNodes.resolve().isEmpty()) {
        Thread.sleep(100L)
    }
    val destName: String = simNodes[random.nextInt(simNodes.size)].name
    val randomDestNodes = actorSystem.actorSelection("SimpleActor://p2p/$destName/session")
    while (randomDestNodes.resolve().isEmpty()) {
        Thread.sleep(100L)
    }
    val randomSourceNode = randomSourceNodes.resolve().single()
    val randomDestNode = randomDestNodes.resolve().single()
    while (true) {
        Thread.sleep(1000L)
        val sourceFut = randomSourceNode.ask<SelfAddressResponse>(SelfAddressRequest())
        try {
            val sourceResult = sourceFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
            sourceAddress = sourceResult.address
        } catch (ex: TimeoutException) {
        }
        if (sourceAddress == null) {
            continue
        }
        val destFut = randomDestNode.ask<SelfAddressResponse>(SelfAddressRequest())
        try {
            val destResult = destFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
            destAddress = destResult.address
        } catch (ex: TimeoutException) {
        }
        if (destAddress == null) {
            continue
        }
        break
    }
    println("using $sourceName $sourceAddress -> $destName $destAddress")
    val closeFut = CompletableFuture<Boolean>()
    val sink = actorSystem.createMessageSink { self, msg, sender ->
        if (msg is SessionStatusInfo) {
            println("New session $msg")
            sender.tell(RemoteConnectionAcknowledge(msg.sessionId, 999, true), self)
            if (msg.status == LinkStatus.LINK_DOWN) {
                closeFut.complete(true)
            }
        } else if (msg is ReceiveSessionData) {
            println("Received ${msg.payload.toString(Charsets.UTF_8)} from ${msg.sessionId}")
        } else {
            println("unknown message type $msg")
        }
    }
    randomDestNode.tell(WatchRequest(), sink)
    var queryNo = 0
    var sessionId: Long
    while (true) {
        Thread.sleep(1000L)
        val sessionSourceNode = actorSystem.actorSelection("SimpleActor://p2p/$sourceName/session")
        println("Send open query")
        val openFut =
            sessionSourceNode.resolve().single().ask<SessionStatusInfo>(OpenSessionRequest(queryNo++, destAddress!!))
        try {
            val destResult = openFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
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
        val sessionSourceNode = actorSystem.actorSelection("SimpleActor://p2p/$sourceName/session").resolve().single()
        println("Send data query $packetNo")
        val sendFut = sessionSourceNode.ask<SendSessionDataAck>(
            SendSessionData(sessionId, "hello$packetNo".toByteArray(Charsets.UTF_8))
        )
        try {
            val destResult = sendFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
            println("result $destResult ${destResult.sessionId} success ${destResult.success} busy ${destResult.busy}")
            if (!destResult.success) {
                println("Session closed terminating early")
                break
            }
            if (!destResult.busy) {
                packetNo++
            } else {
                Thread.sleep(100L)
            }
        } catch (ex: TimeoutException) {
        }
    }
    val sessionNode = actorSystem.actorSelection("SimpleActor://p2p/$sourceName/session")
    sessionNode.tell(CloseSessionRequest(null, sessionId, null), ActorRef.noSender())
    closeFut.get()
    sink.close()
}

private fun pollDht(
    simNodes: MutableList<TreeNode>,
    actorSystem: ActorSystem
) {
    val random = Random()
    var round = 0
    val timeout = Duration.ofSeconds(120L)
    var sinceFailure = 0
    val stored = mutableListOf<Pair<SecureHash, ByteArray>>()
    while (sinceFailure < 10) {
        Thread.sleep(5000L)
        ++round
        var failed = false
        val putTarget = simNodes[random.nextInt(simNodes.size)].name
        val randomPutNode = actorSystem.actorSelection("SimpleActor://p2p/$putTarget/route").resolve().single()
        val data = round.toByteArray()
        val key = SecureHash.secureHash(data)
        val putRequest = ClientDhtRequest(key, data)
        println("send put $round $key to ${randomPutNode.path}")
        val startPut = System.nanoTime()
        val putFut = randomPutNode.ask<ClientDhtResponse>(putRequest)
        try {
            val putResult = putFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
            val diff = ((System.nanoTime() - startPut) / 1000L).toDouble() / 1000.0
            println("put result $putResult in $diff ms ${if (putResult.success) "OK" else "FAIL"}")
            if (!putResult.success) failed = true
            if (putResult.success) {
                stored += Pair(key, data)
            }
        } catch (ex: TimeoutException) {
            println("put query $round timed out FAIL")
            failed = true
        }

        val getTarget = simNodes[random.nextInt(simNodes.size)].name
        val randomGetNode = actorSystem.actorSelection("SimpleActor://p2p/$getTarget/route").resolve().single()
        val (readKey, readData) = if (stored.isEmpty()) {
            Pair(key, data)
        } else {
            stored[random.nextInt(stored.size)]
        }
        val getRequest = ClientDhtRequest(readKey, null)
        println("send get $round $readKey to ${randomGetNode.path}")
        val startGet = System.nanoTime()
        val getFut = randomGetNode.ask<ClientDhtResponse>(getRequest)
        try {
            val getResult = getFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
            val diff = ((System.nanoTime() - startGet) / 1000L).toDouble() / 1000.0
            println("get result $getResult in $diff ms ${if (getResult.success && readData.contentEquals(getResult.data)) "OK" else "FAIL"}")
            if (!getResult.success || !readData.contentEquals(getResult.data)) {
                failed = true
                stored.removeIf { it.first == readKey }
            } else if (stored.size > 5) {
                stored.removeIf { it.first == readKey }
            }
        } catch (ex: TimeoutException) {
            println("get query $round timed out FAIL")
            failed = true
        }
        if (failed) {
            sinceFailure = 0
        } else {
            ++sinceFailure
        }
        println("$sinceFailure rounds since DHT failure")
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

private fun makeBarabasiAlbertNetwork(minDegree: Int, N: Int): Map<Address, Set<Address>> {
    val rand = Random()
    val simNetwork = mutableMapOf<Address, MutableSet<Address>>()
    val allEdges = mutableListOf<Pair<Address, Address>>()
    for (nodeAddress in (1 until minDegree)) {
        val currentNode = NetworkAddress(nodeAddress)
        val currentLinks = simNetwork.getOrPut(currentNode) { mutableSetOf() }
        for (otherAddress in (nodeAddress + 1..minDegree)) {
            val otherNode = NetworkAddress(otherAddress)
            val otherLinks = simNetwork.getOrPut(otherNode) { mutableSetOf() }
            currentLinks += otherNode
            otherLinks += currentNode
            allEdges += Pair(currentNode, otherNode)
        }
    }
    for (nodeAddress in (minDegree + 1..N)) {
        val currentNode = NetworkAddress(nodeAddress)
        val currentLinks = simNetwork.getOrPut(currentNode) { mutableSetOf() }
        while (currentLinks.size < minDegree) {
            val randEdge = allEdges[rand.nextInt(allEdges.size)]
            val otherNode = if (rand.nextBoolean()) randEdge.first else randEdge.second
            if (otherNode in currentLinks) continue
            val otherLinks = simNetwork.getOrPut(otherNode) { mutableSetOf() }
            currentLinks += otherNode
            otherLinks += currentNode
        }
        for (otherNode in currentLinks) {
            allEdges += Pair(currentNode, otherNode)
        }
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
    val networkInfoFile = resourceAsString("as20000102.txt", classLoader)!!
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