package uk.co.nesbit.network.dhtEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.routing.DhtRequest
import uk.co.nesbit.network.api.routing.DhtResponse
import uk.co.nesbit.network.api.routing.ReplyPath
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.time.Duration
import java.time.Instant
import java.util.*
import kotlin.experimental.xor

class ClientDhtRequest(val requestId: Long, val key: SecureHash, val data: ByteArray?)
class ClientDhtResponse(val requestId: Long, val key: SecureHash, val data: ByteArray?)

class DhtRoutingActor(
    private val keyService: KeyService,
    private val neighbourLinkActor: ActorRef
) :
    AbstractActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            neighbourLinkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, neighbourLinkActor)
        }

        const val LINK_CHECK_INTERVAL_MS = 10000L
        const val ALPHA = 5
        const val K = 20

        @JvmStatic
        fun xorDistance(x: SecureHash, y: SecureHash): Int {
            require(x.algorithm == y.algorithm) { "Hashes must be of same type" }
            val xb = x.bytes
            val yb = y.bytes
            var dist = xb.size * 8
            for (i in xb.indices) {
                if (xb[i] == yb[i]) {
                    dist -= 8
                } else {
                    val xorx = Integer.numberOfLeadingZeros(java.lang.Byte.toUnsignedInt(xb[i] xor yb[i]))
                    return dist - xorx + 24
                }
            }
            return dist
        }
    }

    private class TimerTick(val first: Boolean)

    private data class RequestState(
        val startTime: Instant,
        val parent: ClientRequestState?,
        val destination: SecureHash,
        val request: DhtRequest,
        var age: Int = 0
    )

    private data class ClientRequestState(
        val startTime: Instant,
        val sender: ActorRef,
        val request: ClientDhtRequest,
        var outstanding: Int,
        var bestDistance: Int
    )

    private val owners = mutableSetOf<ActorRef>()
    private val sphinxEncoder = Sphinx(keyService.random, 10, 1024)
    private val fullAddresses = mutableMapOf<SecureHash, SphinxPublicIdentity>()
    private val graph = mutableMapOf<SecureHash, MutableMap<SecureHash, Int>>()
    private val outstandingRequests = mutableMapOf<Long, RequestState>()
    private val clientRequests = mutableListOf<ClientRequestState>()
    private val data = mutableMapOf<SecureHash, ByteArray>()
    private var networkAddress: VersionedIdentity? = null
    private var currentNeighbours = emptyList<VersionedIdentity>()
    private var requestId = keyService.random.nextLong()
    private var maxLinkAge = Int.MAX_VALUE
    private var maxRequestAge = Int.MAX_VALUE

    override fun preStart() {
        super.preStart()
        //log().info("Starting DhtRoutingActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
            "dhtLinkStartup",
            TimerTick(true),
            keyService.random.nextInt(LINK_CHECK_INTERVAL_MS.toInt()).toLong().millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped DhtRoutingActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart DhtRoutingActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(NeighbourUpdate::class.java, ::onNeighbourUpdate)
            .match(NeighbourReceivedMessage::class.java, ::onNeighbourReceivedMessage)
            .match(ClientDhtRequest::class.java, ::onClientRequest)
            .match(TimerTick::class.java, ::onTimer)
            .build()

    private fun addNeighbours(neighbours: List<VersionedIdentity>) {
        val neighbourLinks = graph.getOrPut(networkAddress!!.id) { mutableMapOf() }
        for (neighbour in neighbours) {
            fullAddresses[neighbour.id] = neighbour.identity
            neighbourLinks[neighbour.id] = 0
            val links = graph.getOrPut(neighbour.id) { mutableMapOf() }
            links[networkAddress!!.id] = 0
        }
    }

    private fun removeAddress(neighbour: VersionedIdentity) {
        val oldLinks = graph.remove(neighbour.id)
        if (oldLinks != null) {
            for (link in oldLinks.keys) {
                graph[link]?.remove(neighbour.id)
            }
        }
        fullAddresses.remove(neighbour.id)
    }

    private fun insertPath(origin: SecureHash, path: ReplyPath) {
        var prevLinks = graph.getOrPut(origin) { mutableMapOf() }
        var prevAddress = origin
        for (address in path.path) {
            fullAddresses[address.id] = address
            prevLinks[address.id] = 0
            prevLinks = graph.getOrPut(address.id) { mutableMapOf() }
            prevLinks[prevAddress] = 0
            prevAddress = address.id
        }
    }

    private fun getNearestPaths(key: SecureHash, origin: SecureHash, count: Int): MutableList<ReplyPath> {
        val orderedAddresses = fullAddresses.keys.toMutableList()
        orderedAddresses.sortWith(Comparator { x, y ->
            val xorx = xorDistance(x, key)
            val xory = xorDistance(y, key)
            xorx.compareTo(xory)
        })
        val nearestPaths = mutableListOf<ReplyPath>()
        for (address in orderedAddresses) {
            val path = findRandomRoute(origin, address)
            if (path != null && path.isNotEmpty()) {
                nearestPaths += ReplyPath(path)
                if (nearestPaths.size >= count) {
                    break
                }
            }
        }
        return nearestPaths
    }

    private fun ageCache() {
        if (networkAddress == null) return
        val forDelete = mutableListOf<Pair<SecureHash, SecureHash>>()
        var ageTotal = 0
        var linkCount = 0
        for (links in graph) {
            for (link in links.value) {
                val age = link.value + 1
                ageTotal += age
                linkCount++
                link.setValue(age)
                if (age >= maxLinkAge) {
                    forDelete += Pair(links.key, link.key)
                }
            }
        }
        if (linkCount > 0) {
            maxLinkAge = (3 * ageTotal) / linkCount
        }
        for (link in forDelete) {
            val link1 = graph[link.first]
            if (link1 != null) {
                link1.remove(link.second)
                if (link1.isEmpty()) {
                    graph.remove(link.first)
                    fullAddresses.remove(link.first)
                }
            }
            val link2 = graph[link.second]
            if (link2 != null) {
                link2.remove(link.first)
                if (link2.isEmpty()) {
                    graph.remove(link.second)
                    fullAddresses.remove(link.second)
                }
            }

        }
        addNeighbours(currentNeighbours)
        val requestItr = outstandingRequests.iterator()
        var requestAgeTotal = 0
        var requestCount = 0
        while (requestItr.hasNext()) {
            val request = requestItr.next()
            val age = request.value.age + 1
            requestAgeTotal += age
            requestCount++
            request.value.age = age
            if (age > maxRequestAge) {
                requestItr.remove()
                val parent = request.value.parent
                if (parent != null) {
                    --parent.outstanding
                    if (parent.outstanding == 0) {
                        log().info(
                            "Send response timed out ${Duration.between(
                                parent.startTime,
                                Instant.now()
                            ).toMillis()}"
                        )
                        val originalRequest = request.value.request
                        val clientResponse =
                            ClientDhtResponse(originalRequest.requestId, originalRequest.key, originalRequest.data)
                        parent.sender.tell(clientResponse, self)
                    }
                }
            }
        }
        if (requestCount > 0) {
            maxRequestAge = (3 * requestAgeTotal) / requestCount
        }
    }

    private fun send(route: List<SphinxPublicIdentity>, msg: Message) {
        val target = route.last()
        if (target.id == networkAddress!!.id) { // reflect self addressed message
            for (owner in owners) {
                owner.tell(msg, self)
            }
            return
        }
        require(route.all { it.id in fullAddresses }) { "Only able to route to known Sphinx knownAddresses" }
        val routedMessage = RoutedMessage.createRoutedMessage(SphinxAddress(networkAddress!!.identity), msg)

        val sendableMessage = sphinxEncoder.makeMessage(route, routedMessage.serialize())
        neighbourLinkActor.tell(NeighbourSendMessage(route.first(), sendableMessage.messageBytes), self)
    }

    private fun sendDhtProbe(
        parent: ClientRequestState?,
        path: ReplyPath,
        key: SecureHash,
        data: ByteArray?
    ) {
        val target = path.path.last().id
        val reversePath = (listOf(networkAddress!!.identity) + path.path).reversed().drop(1)
        val replyPath = ReplyPath(reversePath)
        val dhtRequest = DhtRequest(requestId++, key, replyPath, data)
        val record = RequestState(Instant.now(), parent, target, dhtRequest)
        outstandingRequests[dhtRequest.requestId] = record
        log().info("send dht ${path.path.last().publicAddress} ${path.path.size} $key")
        send(path.path, dhtRequest)
    }

    private fun getRandomAddress(): SphinxPublicIdentity {
        val randomAddressIndex = keyService.random.nextInt(fullAddresses.size)
        val iter = fullAddresses.iterator()
        for (i in 0 until randomAddressIndex) {
            iter.next()
        }
        return iter.next().value
    }

    private fun findRandomRoute(origin: SecureHash, destination: SecureHash): List<SphinxPublicIdentity>? {
        val rand = Random(keyService.random.nextLong())
        fun randomIterator(nextIndex: Int, scrambledSequence: IntArray): Int {
            // Randomising iterator
            val swapIndex = nextIndex + rand.nextInt(scrambledSequence.size - nextIndex)
            val currentIndex = scrambledSequence[swapIndex]
            scrambledSequence[swapIndex] = scrambledSequence[nextIndex]
            scrambledSequence[nextIndex] = currentIndex
            return currentIndex
        }

        if (destination == origin) {
            return emptyList()
        }
        val maxDepth = sphinxEncoder.maxRouteLength
        var depth = 0
        val iterationStack = IntArray(maxDepth)
        val randomStack = Array(maxDepth) { IntArray(0) }
        val path = Array(maxDepth) { emptyList<SecureHash>() }
        val neighbourRoutes = graph[origin] ?: return null
        path[depth] = neighbourRoutes.map { it.key }
        if (path[depth].isEmpty()) {
            return null
        }
        iterationStack[depth] = 0
        randomStack[depth] = IntArray(path[depth].size) { it }

        while (true) {
            val currentIndex = randomIterator(iterationStack[depth], randomStack[depth])
            val nextNode = path[depth][currentIndex]
            if (nextNode == destination) {
                val output = mutableListOf<SphinxPublicIdentity>()
                for (i in 0..depth) {
                    output += fullAddresses[path[i][randomStack[i][iterationStack[i]]]]!!
                }
                return output
            }
            val nextRoute = graph[nextNode]?.map { it.key }
            var inPrefix = false
            if (nextRoute != null) {
                for (i in 0..depth) {
                    if (path[i] == nextRoute) {
                        inPrefix = true
                        break
                    }
                }
            }
            if (depth < maxDepth - 1 && nextRoute != null && nextRoute.isNotEmpty() && !inPrefix) {
                ++depth
                path[depth] = nextRoute
                iterationStack[depth] = 0
                randomStack[depth] = IntArray(path[depth].size) { it }
            } else {
                while (depth >= 0) {
                    if (iterationStack[depth] < randomStack[depth].size - 1) {
                        ++iterationStack[depth]
                        break
                    } else {
                        --depth
                    }
                }
                if (depth < 0) {
                    return null
                }
            }
        }
    }

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onTimer(tick: TimerTick) {
        if (tick.first) {
            timers.startPeriodicTimer(
                "dhtLinkPoller",
                TimerTick(false),
                LINK_CHECK_INTERVAL_MS.millis()
            )
        }
        if (networkAddress == null || fullAddresses.isEmpty()) {
            return
        }
        ageCache()
        log().info("Total addresses ${fullAddresses.size}")
        if (outstandingRequests.isNotEmpty()) {
            return
        }
        val nearestPaths = getNearestPaths(networkAddress!!.id, networkAddress!!.id, ALPHA)
        for (path in nearestPaths) {
            sendDhtProbe(null, path, networkAddress!!.id, networkAddress!!.serialize())
        }
//        val randomAddress = getRandomAddress()
//        val randomPath = findRandomRoute(networkAddress!!.id, randomAddress.id)
//        if (randomPath != null && randomPath.isNotEmpty()) {
//            sendDhtProbe(null, ReplyPath(randomPath), networkAddress!!.id, networkAddress!!.serialize())
//        }
    }

    private fun onNeighbourUpdate(neighbours: NeighbourUpdate) {
        //log().info("onNeighbourUpdate ${neighbours.addresses.map { it.identity.publicAddress }}")
        val oldNeighbours = currentNeighbours
        for (neighbour in oldNeighbours) {
            removeAddress(neighbour)
        }
        networkAddress = neighbours.localId
        fullAddresses[neighbours.localId.id] = neighbours.localId.identity
        currentNeighbours = neighbours.addresses
        addNeighbours(neighbours.addresses)
    }

    private fun onNeighbourReceivedMessage(msg: NeighbourReceivedMessage) {
        if (networkAddress == null) {
            log().warning("Dropping packet! Don't know local address yet")
            return
        }
        val messageResult = sphinxEncoder.processMessage(
            msg.msg,
            networkAddress!!.id
        ) { remotePubKey -> keyService.getSharedDHSecret(networkAddress!!.id, remotePubKey) }
        if (messageResult.valid) {
            if (messageResult.finalPayload != null) {
                val routedMessage = try {
                    RoutedMessage.deserialize(messageResult.finalPayload!!)
                } catch (ex: Exception) {
                    log().error("Bad message")
                    return
                }
                when {
                    routedMessage.payloadSchemaId.contentEquals(DhtRequest.schemaFingerprint) -> processRequest(
                        DhtRequest.deserialize(routedMessage.payload)
                    )
                    routedMessage.payloadSchemaId.contentEquals(DhtResponse.schemaFingerprint) -> processResponse(
                        DhtResponse.deserialize(routedMessage.payload)
                    )
                    else -> {
                        for (owner in owners) {
                            owner.tell(routedMessage, self)
                        }
                    }
                }
            } else {
                val nextAddress = fullAddresses[messageResult.nextNode!!]
                if (nextAddress == null) {
                    log().warning("Dropping packet! Don't know next address ${messageResult.nextNode}")
                    return
                }
                neighbourLinkActor.tell(
                    NeighbourSendMessage(
                        nextAddress,
                        messageResult.forwardMessage!!.messageBytes
                    ), self
                )
                return
            }
        } else {
            log().error("Bad message received")
        }
    }

    private fun processRequest(request: DhtRequest) {
        //log().info("got request")
        insertPath(networkAddress!!.id, request.replyPath)
        if (request.data != null) {
            data[request.key] = request.data
        }
        val replyAddress = request.replyPath.path.last()
        val nearestPaths = getNearestPaths(request.key, replyAddress.id, K)
        val response = DhtResponse(request.requestId, nearestPaths, data[request.key])
        send(request.replyPath.path, response)
    }

    private fun processResponse(response: DhtResponse) {
        val originalRequest = outstandingRequests.remove(response.requestId) ?: return
        log().info("got response ${Duration.between(originalRequest.startTime, Instant.now()).toMillis()}")
        val neigbourSet = currentNeighbours.map { it.identity }.toSet()
        for (path in response.nearestPaths) {
            if (path.path.isEmpty()) {
                log().error("Bad response contains empty path")
                return
            }
            if (path.path.contains(networkAddress!!.identity)) {
                log().error("Bad response contains our address")
                return
            }
            if (path.path.first() !in neigbourSet) {
                log().error("Bad response path doesn't start with a valid local neighbour")
                return
            }
        }
        for (path in response.nearestPaths) {
            insertPath(networkAddress!!.id, path)
        }
        //log().info("Total addresses ${fullAddresses.size}")
        val clientRequestState = originalRequest.parent
        if (clientRequestState != null && clientRequests.contains(clientRequestState)) {
            --clientRequestState.outstanding
            val originalClientRequest = clientRequestState.request
            if (originalClientRequest.data == null && response.data != null) {
                log().info(
                    "send response got data ${Duration.between(
                        clientRequestState.startTime,
                        Instant.now()
                    ).toMillis()} ${originalClientRequest.requestId} ${originalClientRequest.key} ${response.data.toString(
                        Charsets.UTF_8
                    )}"
                )
                val clientResponse = ClientDhtResponse(
                    originalClientRequest.requestId,
                    originalClientRequest.key,
                    response.data
                )
                clientRequestState.sender.tell(clientResponse, self)
                clientRequests.remove(clientRequestState)
            } else {
                val newPaths = getNearestPaths(originalClientRequest.key, networkAddress!!.id, K)
                var bestDistance = clientRequestState.bestDistance
                for (newPath in newPaths) {
                    val target = newPath.path.last()
                    val distance = xorDistance(target.id, originalClientRequest.key)
                    if (distance < clientRequestState.bestDistance) {
                        log().info("Able to query nearer: $distance requestId: ${originalClientRequest.requestId} key: ${originalClientRequest.key}")
                        bestDistance = distance
                        ++clientRequestState.outstanding
                        sendDhtProbe(clientRequestState, newPath, originalClientRequest.key, originalClientRequest.data)
                    }
                }
                clientRequestState.bestDistance = bestDistance
                if (clientRequestState.outstanding == 0) {
                    if (originalClientRequest.data == null) {
                        log().info(
                            "send response ${Duration.between(
                                clientRequestState.startTime,
                                Instant.now()
                            ).toMillis()} no better path ${originalClientRequest.requestId} ${originalClientRequest.key}"
                        )
                    } else {
                        log().info(
                            "send response ${Duration.between(
                                clientRequestState.startTime,
                                Instant.now()
                            ).toMillis()} done ${originalClientRequest.requestId} ${originalClientRequest.key}"
                        )
                    }
                    val clientResponse = ClientDhtResponse(
                        originalClientRequest.requestId,
                        originalClientRequest.key,
                        response.data
                    )
                    clientRequestState.sender.tell(clientResponse, self)
                    clientRequests.remove(clientRequestState)
                }
            }
        }
    }

    private fun onClientRequest(request: ClientDhtRequest) {
        log().info("onClientRequest ${request.requestId} ${request.key} ${request.data?.toString(Charsets.UTF_8)}")
        if (fullAddresses.isEmpty()) {
            log().info("Send response not ready")
            val reply = ClientDhtResponse(request.requestId, request.key, null)
            sender.tell(reply, self)
            return
        }
        val nearestPaths = getNearestPaths(request.key, networkAddress!!.id, ALPHA)
        if (nearestPaths.isEmpty()) {
            log().info("Send response no nearest neighbour")
            val reply = ClientDhtResponse(request.requestId, request.key, null)
            sender.tell(reply, self)
            return
        }
        val nearestTarget = nearestPaths.first().path.last().id
        val clientRequestState =
            ClientRequestState(
                Instant.now(),
                sender,
                request,
                nearestPaths.size,
                xorDistance(nearestTarget, request.key)
            )
        clientRequests += clientRequestState
        for (path in nearestPaths) {
            sendDhtProbe(clientRequestState, path, request.key, request.data)
        }
    }
}