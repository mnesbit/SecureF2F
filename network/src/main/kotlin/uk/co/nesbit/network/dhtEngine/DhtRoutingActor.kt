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

    private val owners = mutableSetOf<ActorRef>()
    private val sphinxEncoder = Sphinx(keyService.random, 10, 1024)
    private val fullAddresses = mutableMapOf<SecureHash, SphinxPublicIdentity>()
    private val graph = mutableMapOf<SecureHash, MutableSet<SecureHash>>()
    private val data = mutableMapOf<SecureHash, ByteArray>()
    private var networkAddress: VersionedIdentity? = null
    private var currentNeighbours = emptyList<VersionedIdentity>()
    private var requestId = keyService.random.nextLong()

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
        val neighbourLinks = graph.getOrPut(networkAddress!!.id) { mutableSetOf() }
        for (neighbour in neighbours) {
            fullAddresses[neighbour.id] = neighbour.identity
            neighbourLinks += neighbour.id
            val links = graph.getOrPut(neighbour.id) { mutableSetOf() }
            links += networkAddress!!.id
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
        var prevLinks = graph.getOrPut(origin) { mutableSetOf() }
        var prevAddress = origin
        for (address in path.path) {
            fullAddresses[address.id] = address
            prevLinks.add(address.id)
            prevLinks = graph.getOrPut(address.id) { mutableSetOf() }
            prevLinks.add(prevAddress)
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
        path[depth] = neighbourRoutes.toList()
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
            val nextRoute = graph[nextNode]?.toList()
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
        log().info("Total addresses ${fullAddresses.size}")
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

    }

    private fun processResponse(response: DhtResponse) {

    }

    private fun onClientRequest(request: ClientDhtRequest) {

    }
}