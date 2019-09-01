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
import java.util.*
import kotlin.experimental.xor

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

        const val LINK_CHECK_INTERVAL_MS = 1000L
        const val K = 5
        const val MAX_AGE = 10

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

    private class CheckDhtEntries
    private data class RequestRecord(val destination: SecureHash, val request: DhtRequest)

    private val owners = mutableSetOf<ActorRef>()
    private val sphinxEncoder = Sphinx(keyService.random, 5, 1024)
    private val fullAddresses = mutableMapOf<SecureHash, SphinxPublicIdentity>()
    private val graph = mutableMapOf<SecureHash, MutableMap<SecureHash, Int>>()
    private val outstandingRequests = mutableMapOf<Long, RequestRecord>()
    private var networkAddress: VersionedIdentity? = null
    private var currentNeighbours = emptyList<VersionedIdentity>()
    private var requestId = keyService.random.nextLong()

    override fun preStart() {
        super.preStart()
        //log().info("Starting DhtRoutingActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startPeriodicTimer(
            "dhtLinkPoller",
            CheckDhtEntries(),
            LINK_CHECK_INTERVAL_MS.millis()
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
            .match(CheckDhtEntries::class.java) { onCheckDhtEntries() }
            .build()

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onNeighbourUpdate(neighbours: NeighbourUpdate) {
        //log().info("onNeighbourUpdate ${neighbours.addresses.map { it.identity.publicAddress }}")
        val oldNeighbours = currentNeighbours
        for (neighbour in oldNeighbours) {
            val oldLinks = graph.remove(neighbour.id)
            if (oldLinks != null) {
                for (link in oldLinks.keys) {
                    graph[link]?.remove(neighbour.id)
                }
            }
            fullAddresses.remove(neighbour.id)
        }
        networkAddress = neighbours.localId
        fullAddresses[neighbours.localId.id] = neighbours.localId.identity
        currentNeighbours = neighbours.addresses
        val neighbourLinks = graph.getOrPut(networkAddress!!.id) { mutableMapOf() }
        for (neighbour in currentNeighbours) {
            fullAddresses[neighbour.id] = neighbour.identity
            neighbourLinks[neighbour.id] = 0
            val links = graph.getOrPut(neighbour.id) { mutableMapOf() }
            links[networkAddress!!.id] = 0
        }
    }

    private fun send(route: List<SphinxPublicIdentity>, msg: Message) {
        val routedMessage = RoutedMessage.createRoutedMessage(SphinxAddress(networkAddress!!.identity), msg)
        require(route.all { it.id in fullAddresses }) { "Only able to route to known Sphinx knownAddresses" }
        val target = route.last()
        if (target.id == networkAddress!!.id) { // reflect self addressed message
            for (owner in owners) {
                owner.tell(msg, self)
            }
            return
        }
        val sendableMessage = sphinxEncoder.makeMessage(route, routedMessage.serialize())
        neighbourLinkActor.tell(NeighbourSendMessage(route.first(), sendableMessage.messageBytes), self)
    }

    private fun onNeighbourReceivedMessage(msg: NeighbourReceivedMessage) {
        if (networkAddress == null) {
            log().warning("Dropping packet! Don't know local address")
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
                if (nextAddress != null) {
                    neighbourLinkActor.tell(
                        NeighbourSendMessage(
                            nextAddress,
                            messageResult.forwardMessage!!.messageBytes
                        ), self
                    )
                    return
                }
                log().warning("Dropping packet! Don't know next address ${messageResult.nextNode}")
            }
        } else {
            log().error("Bad message received")
        }
    }

    private fun processRequest(request: DhtRequest) {
        log().info("got request")
        insertPath(networkAddress!!.id, request.replyPath)
        val replyAddress = request.replyPath.path.last()
        val orderedAddresses = fullAddresses.keys.toMutableList()
        orderedAddresses.sortWith(Comparator { x, y ->
            val xorx = xorDistance(networkAddress!!.id, x)
            val xory = xorDistance(networkAddress!!.id, y)
            xorx.compareTo(xory)
        })
        val nearestAddresses = mutableListOf<SecureHash>()
        for (item in orderedAddresses) {
            val path = findRandomRouteTo(item, replyAddress.id)
            if (path != null) {
                nearestAddresses += item
                if (nearestAddresses.size > K) break
            }
        }
        val nearestPaths = nearestAddresses.mapNotNull { findRandomRouteTo(it, replyAddress.id) }.map { ReplyPath(it) }
        val response = DhtResponse(requestId, nearestPaths, currentNeighbours.map { it.identity }, null)
        send(request.replyPath.path, response)
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

    private fun processResponse(response: DhtResponse) {
        log().info("got response")
        val originalRequest = outstandingRequests.remove(response.requestId) ?: return
        val destLinks = graph.getOrPut(originalRequest.destination) { mutableMapOf() }
        for (address in response.directNeighbours) {
            fullAddresses[address.id] = address
            destLinks[address.id] = 0
            val links = graph.getOrPut(address.id) { mutableMapOf() }
            links[originalRequest.destination] = 0
        }
        for (path in response.nearestPaths) {
            insertPath(originalRequest.destination, path)
        }
    }

    private fun onCheckDhtEntries() {
        if (fullAddresses.isEmpty()) return
        val randomAddress = getRandomAddress()
        if (randomAddress == networkAddress?.identity) return
        val route = findRandomRouteTo(networkAddress!!.id, randomAddress.id) ?: return
        val reversePath = (listOf(networkAddress!!.identity) + route).reversed().drop(1)
        val replyPath = ReplyPath(reversePath)
        val dhtRequest = DhtRequest(requestId++, networkAddress!!.id, replyPath, networkAddress!!.serialize())
        outstandingRequests[dhtRequest.requestId] = RequestRecord(randomAddress.id, dhtRequest)
        send(route, dhtRequest)
    }

    private fun getRandomAddress(): SphinxPublicIdentity {
        val randomAddressIndex = keyService.random.nextInt(fullAddresses.size)
        val iter = fullAddresses.iterator()
        for (i in 0 until randomAddressIndex) {
            iter.next()
        }
        return iter.next().value
    }

    private fun findRandomRouteTo(origin: SecureHash, destination: SecureHash): List<SphinxPublicIdentity>? {
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

}