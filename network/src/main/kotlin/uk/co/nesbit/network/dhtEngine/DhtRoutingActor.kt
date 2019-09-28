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

        const val LINK_CHECK_INTERVAL_MS = 1000L
        const val ALPHA = 5
        const val K = 20
        const val MAX_AGE = 25
        const val REQUEST_TIMEOUT = 5

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

    private class TimerTick
    private data class RequestRecord(val destination: SecureHash, val request: DhtRequest, var age: Int = 0)

    private val owners = mutableSetOf<ActorRef>()
    private val sphinxEncoder = Sphinx(keyService.random, 5, 1024)
    private val fullAddresses = mutableMapOf<SecureHash, SphinxPublicIdentity>()
    private val graph = mutableMapOf<SecureHash, MutableMap<SecureHash, Int>>()
    private val outstandingRequests = mutableMapOf<Long, RequestRecord>()
    private val data = mutableMapOf<SecureHash, ByteArray>()
    private var networkAddress: VersionedIdentity? = null
    private var currentNeighbours = emptyList<VersionedIdentity>()
    private var requestId = keyService.random.nextLong()

    override fun preStart() {
        super.preStart()
        //log().info("Starting DhtRoutingActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startPeriodicTimer(
            "dhtLinkPoller",
            TimerTick(),
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
            .match(TimerTick::class.java) {
                refreshOwnEntry()
                ageCache()
            }
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
            removeAddress(neighbour)
        }
        networkAddress = neighbours.localId
        fullAddresses[neighbours.localId.id] = neighbours.localId.identity
        currentNeighbours = neighbours.addresses
        addNeighbours(neighbours.addresses)
    }

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

    private fun ageCache() {
        if (networkAddress == null) return
        val forDelete = mutableListOf<Pair<SecureHash, SecureHash>>()
        for (links in graph) {
            for (link in links.value) {
                val age = link.value + 1
                link.setValue(age)
                if (age >= MAX_AGE) {
                    forDelete += Pair(links.key, link.key)
                }
            }
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
        while (requestItr.hasNext()) {
            val request = requestItr.next()
            val age = request.value.age + 1
            request.value.age = age
//            if(age < REQUEST_TIMEOUT) {
//                request.value.age = age
//            } else {
//                log().info("request timed out")
//                requestItr.remove()
//            }
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
        log().info("got request")
        insertPath(networkAddress!!.id, request.replyPath)
        if (request.data != null) {
            data[request.key] = request.data
        }
        val replyAddress = request.replyPath.path.last()
        val nearestPaths = getNearestKPaths(request.key, replyAddress.id)
        val response = DhtResponse(request.requestId, nearestPaths, data[request.key])
        send(request.replyPath.path, response)
    }

    private fun processResponse(response: DhtResponse) {
        val originalRequest = outstandingRequests.remove(response.requestId) ?: return
        log().info("got response aged ${originalRequest.age}")
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
        log().info("Total addresses ${fullAddresses.size}")
    }

    private fun refreshOwnEntry() {
        if (fullAddresses.isEmpty()) return
        val nearestPaths = getNearestKPaths(networkAddress!!.id, networkAddress!!.id)
        if (nearestPaths.isEmpty()) return
        val index = keyService.random.nextInt(nearestPaths.size)
        val route = nearestPaths[index].path
        val reversePath = (listOf(networkAddress!!.identity) + route).reversed().drop(1)
        val replyPath = ReplyPath(reversePath)
        val dhtRequest = DhtRequest(requestId++, networkAddress!!.id, replyPath, networkAddress!!.serialize())
        outstandingRequests[dhtRequest.requestId] = RequestRecord(route.last().id, dhtRequest)
        send(route, dhtRequest)
    }

    private fun getNearestKPaths(key: SecureHash, origin: SecureHash): MutableList<ReplyPath> {
        val orderedAddresses = fullAddresses.keys.toMutableList()
        orderedAddresses.sortWith(Comparator { x, y ->
            val xorx = xorDistance(key, x)
            val xory = xorDistance(key, y)
            xorx.compareTo(xory)
        })
        val nearestPaths = mutableListOf<ReplyPath>()
        for (item in orderedAddresses) {
            val path = findRandomRoute(origin, item)
            if (path != null && path.isNotEmpty()) {
                nearestPaths += ReplyPath(path)
                if (nearestPaths.size > ALPHA) break
            }
        }
        return nearestPaths
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

}