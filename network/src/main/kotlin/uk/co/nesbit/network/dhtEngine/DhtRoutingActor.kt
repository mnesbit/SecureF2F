package uk.co.nesbit.network.dhtEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.SecureHash.Companion.xorDistance
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
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import java.lang.Integer.min
import java.time.Duration
import java.time.Instant
import java.util.*

class ClientDhtRequest(val requestId: Long, val key: SecureHash, val data: ByteArray?)
class ClientDhtResponse(val requestId: Long, val key: SecureHash, val data: ByteArray?)
class GetInfoRequest
class GetInfoResponse(val address: VersionedIdentity?, val kpaths: List<ReplyPath>)

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

        const val ALPHA = 5
        const val K = 15
    }

    private class Scan

    private class RequestState(
        val sendTime: Instant,
        val parent: ClientRequestState?,
        val target: SecureHash,
        val request: DhtRequest
    )

    private class ClientRequestState(
        val sendTime: Instant,
        val sender: ActorRef,
        val request: ClientDhtRequest,
        val probes: MutableSet<SecureHash> = mutableSetOf(),
        var responses: Int = 0
    )

    private val owners = mutableSetOf<ActorRef>()
    private val sphinxEncoder = Sphinx(keyService.random, 10, 1024)
    private val fullAddresses = mutableMapOf<SecureHash, SphinxPublicIdentity>()
    private val graph = mutableMapOf<SecureHash, MutableList<SecureHash>>()
    private val data = mutableMapOf<SecureHash, ByteArray>()
    private val outstandingRequests = mutableMapOf<Long, RequestState>()
    private val outstandingClientRequests = mutableMapOf<Long, ClientRequestState>()
    private var networkAddress: VersionedIdentity? = null
    private var currentNeighbours = emptyList<VersionedIdentity>()
    private var requestId = keyService.random.nextLong()

    override fun preStart() {
        super.preStart()
        //log().info("Starting DhtRoutingActor")
        neighbourLinkActor.tell(WatchRequest(), self)
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
            .match(Scan::class.java) { onScan() }
            .match(GetInfoRequest::class.java) {
                log().info("Queried")
                if (networkAddress == null) {
                    sender.tell(GetInfoResponse(networkAddress, emptyList()), self)
                } else {
                    val kPaths = getNearestPaths(networkAddress!!.id, networkAddress!!.id, K)
                    sender.tell(GetInfoResponse(networkAddress, kPaths), self)
                }
            }
            .build()

    private fun addNeighbours(neighbours: List<VersionedIdentity>) {
        val neighbourLinks = graph.getOrPut(networkAddress!!.id) { mutableListOf() }
        for (neighbour in neighbours) {
            fullAddresses[neighbour.id] = neighbour.identity
            if (!neighbourLinks.contains(neighbour.id)) {
                neighbourLinks += neighbour.id
            }
            val links = graph.getOrPut(neighbour.id) { mutableListOf() }
            if (!links.contains(networkAddress!!.id)) {
                links += networkAddress!!.id
            }
        }
    }

    private fun removeAddress(neighbour: SecureHash) {
        val oldLinks = graph.remove(neighbour)
        if (oldLinks != null) {
            for (link in oldLinks) {
                graph[link]?.remove(neighbour)
            }
        }
        fullAddresses.remove(neighbour)
    }

    private fun insertPath(origin: SecureHash, path: ReplyPath) {
        var prevLinks = graph.getOrPut(origin) { mutableListOf() }
        var prevAddress = origin
        for (address in path.path) {
            fullAddresses[address.id] = address
            if (!prevLinks.contains(address.id)) {
                prevLinks.add(address.id)
            }
            prevLinks = graph.getOrPut(address.id) { mutableListOf() }
            if (!prevLinks.contains(prevAddress)) {
                prevLinks.add(prevAddress)
            }
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
        if (parent != null) {
            parent.probes += target
        }
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
        if (origin == networkAddress?.id && currentNeighbours.any { it.id == destination }) {
            return listOf(fullAddresses[destination]!!)
        }
        val rand = Random(System.nanoTime())
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
        path[depth] = graph[origin] ?: return null
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
            val nextRoute = graph[nextNode]
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

    private fun onScan() {
        if (networkAddress == null || fullAddresses.isEmpty()) {
            return
        }
        log().info("Total addresses ${fullAddresses.size}")
        val paths = getNearestPaths(networkAddress!!.id, networkAddress!!.id, 2 * K + 1)
        if (paths.isEmpty()) {
            return
        }
        if (paths.size > 2 * K) {
            graph.clear()
            fullAddresses.clear()
            fullAddresses[networkAddress!!.id] = networkAddress!!.identity
            addNeighbours(currentNeighbours)
            for (path in paths.take(2 * K)) {
                insertPath(networkAddress!!.id, path)
            }
        }
        val index = keyService.random.nextInt(min(paths.size, 2 * K))
        sendDhtProbe(null, paths[index], networkAddress!!.id, networkAddress!!.serialize())
    }

    private fun onNeighbourUpdate(neighbours: NeighbourUpdate) {
        //log().info("onNeighbourUpdate ${neighbours.addresses.map { it.identity.publicAddress }}")
        val oldNeighbours = currentNeighbours
        for (neighbour in oldNeighbours) {
            removeAddress(neighbour.id)
        }
        networkAddress = neighbours.localId
        fullAddresses[neighbours.localId.id] = neighbours.localId.identity
        currentNeighbours = neighbours.addresses
        addNeighbours(neighbours.addresses)
        self.tell(Scan(), self)
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
        log().info("got request ${request.key}")
        val firstHop = request.replyPath.path.first().id
        if (!currentNeighbours.any { firstHop == it.id }) {
            log().error("Bad request reply path")
            return
        }
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
        if (outstandingRequests.isEmpty()) {
            self.tell(Scan(), self)
        }
        log().info("got response ${Duration.between(originalRequest.sendTime, Instant.now()).toMillis()}")
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
        if (originalRequest.request.data == null && response.data != null) {
            data[originalRequest.request.key] = response.data
        }
        val parent = originalRequest.parent
        if (parent != null) {
            val originalClientRequestState = outstandingClientRequests[parent.request.requestId]
            if (originalClientRequestState != null) {
                val originalClientRequest = originalClientRequestState.request
                log().info("got client related response ${originalClientRequest.key}")
                originalClientRequestState.responses += 1
                if (originalClientRequest.data == null && response.data != null) {
                    log().info(
                        "got client data in ${Duration.between(
                            originalRequest.sendTime,
                            Instant.now()
                        ).toMillis()}"
                    )
                    val clientResponse = ClientDhtResponse(
                        originalClientRequest.requestId,
                        originalClientRequest.key,
                        response.data
                    )
                    outstandingClientRequests.remove(originalClientRequest.requestId)
                    originalClientRequestState.sender.tell(clientResponse, self)
                    return
                }
                val nearestPaths = getNearestPaths(originalClientRequest.key, networkAddress!!.id, ALPHA)
                for (path in nearestPaths) {
                    if (path.path.last().id !in originalClientRequestState.probes) {
                        log().info("improve client search")
                        sendDhtProbe(
                            originalClientRequestState,
                            path,
                            originalClientRequest.key,
                            originalClientRequest.data
                        )
                    }
                }
                if (originalClientRequestState.probes.size == originalClientRequestState.responses) {
                    log().info("All ${originalClientRequestState.responses} client responses done")
                    val clientResponse = ClientDhtResponse(
                        originalClientRequest.requestId,
                        originalClientRequest.key,
                        null
                    )
                    outstandingClientRequests.remove(originalClientRequest.requestId)
                    originalClientRequestState.sender.tell(clientResponse, self)
                }
            }
        }
    }

    private fun onClientRequest(request: ClientDhtRequest) {
        log().info("got client request ${request.key}")
        val requestState = ClientRequestState(Instant.now(), sender, request)
        outstandingClientRequests[request.requestId] = requestState
        val paths = getNearestPaths(request.key, networkAddress!!.id, ALPHA)
        for (path in paths) {
            sendDhtProbe(requestState, path, request.key, request.data)
        }
    }
}