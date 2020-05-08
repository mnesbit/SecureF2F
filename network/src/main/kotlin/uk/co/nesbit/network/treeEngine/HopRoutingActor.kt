package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import com.github.benmanes.caffeine.cache.Caffeine
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.Ecies
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.*
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.lang.Long.max
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.experimental.xor

class HopRoutingActor(
    private val keyService: KeyService,
    private val networkConfig: NetworkConfiguration,
    private val neighbourLinkActor: ActorRef
) :
    UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            networkConfig: NetworkConfiguration,
            neighbourLinkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, networkConfig, neighbourLinkActor)
        }

        const val ROUTE_CHECK_INTERVAL_MS = 15000L
        const val REQUEST_TIMEOUT_INCREMENT_MS = 1000L
        const val GAP_CALC_STABLE = 3
        const val ALPHA = 3
        const val K = 15

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

        val bestDist = ConcurrentHashMap<SecureHash, Int>()
        val gapZero = AtomicInteger(0)
    }

    private class CheckRoutes(val first: Boolean)
    private class KBucket(
        val xorDistanceMin: Int, // inclusive
        val xorDistanceMax: Int // exclusive
    ) {
        val nodes: MutableList<NetworkAddressInfo> = mutableListOf()
    }

    private class RequestTracker(val request: DhtRequest, val sent: Instant, val target: NetworkAddressInfo)

    private val owners = mutableSetOf<ActorRef>()
    private var networkAddress: NetworkAddressInfo? = null
    private val neighbours = mutableMapOf<SecureHash, NetworkAddressInfo>()
    private val sphinxEncoder = Sphinx(keyService.random, 15, 1024)
    private val kbuckets = mutableListOf(KBucket(0, 257))
    private var bucketRefresh: Int = 0
    private var round: Int = 0
    private var gapNEstimate: Int = 0
    private var gapCalcStable: Int = 0
    private var gapZeroDone = false
    private var requestId: Long = 0L
    private val outstandingRequests = mutableMapOf<Long, RequestTracker>()
    private var requestTimeout: Long = ROUTE_CHECK_INTERVAL_MS
    private val routeCache = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, List<VersionedIdentity>>()
    private val data = mutableMapOf<SecureHash, ByteArray>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting NeighbourLinkActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
            "routeScanningStartup",
            CheckRoutes(true),
            keyService.random.nextInt(ROUTE_CHECK_INTERVAL_MS.toInt()).toLong().millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped NeighbourLinkActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart NeighbourLinkActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is CheckRoutes -> onCheckRoutes(message)
            is WatchRequest -> onWatchRequest()
            is NeighbourUpdate -> onNeighbourUpdate(message)
            is NeighbourReceivedGreedyMessage -> onNeighbourReceivedGreedyMessage(message)
            is SphinxRoutedMessage -> onSphinxRoutedMessage(message)
            else -> throw IllegalArgumentException("Unknown message type")
        }
    }

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onCheckRoutes(check: CheckRoutes) {
        if (check.first) {
            timers.startTimerWithFixedDelay(
                "routeScanningPoller",
                CheckRoutes(false),
                ROUTE_CHECK_INTERVAL_MS.millis()
            )
        }
        if (networkAddress == null) {
            return
        }
        val distMin = calcNearestNodeGap()
        val now = Clock.systemUTC().instant()
        val requestItr = outstandingRequests.iterator()
        while (requestItr.hasNext()) {
            val request = requestItr.next()
            if (ChronoUnit.MILLIS.between(request.value.sent, now) >= requestTimeout) {
                //log().info("stale request")
                requestItr.remove()
                val bucket = findBucket(request.value.request.key)
                if (bucket.nodes.remove(request.value.target)) { // move to end
                    bucket.nodes.add(request.value.target)
                }
                routeCache.invalidate(request.value.target.identity.id) // don't trust sphinx route
                requestTimeout += REQUEST_TIMEOUT_INCREMENT_MS
            }
        }
        if (outstandingRequests.isEmpty()) {
            val nearest = findNearest(networkAddress!!.identity.id, ALPHA)
            round++

            logNearestNodeGap(nearest, distMin)
            for (near in nearest) {
                val nearestTo = findBucket(near.identity.id)
                val request = DhtRequest(
                    requestId++,
                    networkAddress!!.identity.id,
                    networkAddress!!,
                    nearestTo.nodes,
                    networkAddress!!.serialize()
                )
                outstandingRequests[request.requestId] = RequestTracker(request, now, near)
                sendGreedyMessage(near, request)
            }
            bucketRefresh = bucketRefresh.rem(kbuckets.size)
            val randomBucket = kbuckets[bucketRefresh]
            bucketRefresh = (bucketRefresh + 1).rem(kbuckets.size)
            if (randomBucket.nodes.isNotEmpty()) {
                val target = randomBucket.nodes[keyService.random.nextInt(randomBucket.nodes.size)]
                val nearestTo = findBucket(target.identity.id)
                val request = DhtRequest(
                    requestId++,
                    networkAddress!!.identity.id,
                    networkAddress!!,
                    nearestTo.nodes,
                    networkAddress!!.serialize()
                )
                outstandingRequests[request.requestId] = RequestTracker(request, now, target)
                sendGreedyMessage(target, request)
            }
        }
    }

    private fun logNearestNodeGap(
        nearest: List<NetworkAddressInfo>,
        distMin: Int
    ) {
        if ((gapCalcStable >= GAP_CALC_STABLE) && nearest.isNotEmpty()) {
            val gap = xorDistance(nearest.first().identity.id, networkAddress!!.identity.id) - distMin
            if (gap == 0 && !gapZeroDone) {
                gapZero.incrementAndGet()
                gapZeroDone = true
            }
            log().info("gap $gap $round ${(100 * gapZero.get()) / gapNEstimate}")
        }
    }

    private fun calcNearestNodeGap(): Int {
        var distMin = 258
        if (gapCalcStable < GAP_CALC_STABLE) {
            gapCalcStable++
            for (key in bestDist.keys()) {
                val dist = xorDistance(networkAddress!!.identity.id, key)
                if (dist != 0) {
                    distMin = kotlin.math.min(dist, distMin)
                }
            }
            if (!bestDist.containsKey(networkAddress!!.identity.id)
                || gapNEstimate != bestDist.size
                || bestDist[networkAddress!!.identity.id] != distMin
            ) {
                bestDist[networkAddress!!.identity.id] = distMin
                gapCalcStable = 0
                gapNEstimate = bestDist.size
            }
        } else {
            distMin = bestDist[networkAddress!!.identity.id]!!
        }
        return distMin
    }

    private fun sendGreedyMessage(
        destination: NetworkAddressInfo,
        message: Message
    ) {
        val cachedPrivateRoute = routeCache.getIfPresent(destination.identity.id)
        if (cachedPrivateRoute != null) {
            sendSphinxMessage(cachedPrivateRoute, message)
            return
        }
        val wrapper = OneHopMessage.createOneHopMessage(0, 0, message)
        val encrypted = Ecies.encryptMessage(
            wrapper.serialize(),
            null,
            destination.identity.identity.diffieHellmanPublicKey,
            keyService.random
        )
        val sendRequest = NeighbourSendGreedyMessage(destination, encrypted)
        neighbourLinkActor.tell(sendRequest, self)
    }

    private fun sendSphinxMessage(
        replyRoute: List<VersionedIdentity>,
        message: Message
    ) {
        val wrapper = OneHopMessage.createOneHopMessage(0, 0, message)
        val sphinxMessage = sphinxEncoder.makeMessage(
            replyRoute.map { it.identity },
            wrapper.serialize(),
            keyService.random
        )
        val sphinxRoutedMessage = SphinxRoutedMessage(sphinxMessage.messageBytes)
        val neighbourSend = NeighbourSendSphinxMessage(replyRoute.first().id, sphinxRoutedMessage)
        neighbourLinkActor.tell(neighbourSend, self)
    }

    private fun findBucket(id: SecureHash): KBucket {
        val dist = xorDistance(networkAddress!!.identity.id, id)
        return kbuckets.first { it.xorDistanceMin <= dist && dist < it.xorDistanceMax }
    }

    private fun addToKBuckets(node: NetworkAddressInfo) {
        if (node.treeAddress.first() != networkAddress!!.treeAddress.first()) {
            return
        }
        if (node.identity.id == networkAddress?.identity?.id) {
            return
        }
        val bucket = findBucket(node.identity.id)
        bucket.nodes.removeIf { it.identity.id == node.identity.id }
        if (bucket.nodes.size >= K) {
            bucket.nodes.add(0, node)
            if (bucket.xorDistanceMax - bucket.xorDistanceMin > 1) {
                val sorted = bucket.nodes.sortedBy {
                    xorDistance(networkAddress!!.identity.id, it.identity.id)
                }
                val mid = sorted[sorted.size / 2]
                val midDist = xorDistance(networkAddress!!.identity.id, mid.identity.id)
                val leftBucket = KBucket(bucket.xorDistanceMin, midDist)
                leftBucket.nodes.addAll(bucket.nodes.filter {
                    xorDistance(
                        networkAddress!!.identity.id,
                        it.identity.id
                    ) < midDist
                })
                val rightBucket = KBucket(midDist, bucket.xorDistanceMax)
                rightBucket.nodes.addAll(bucket.nodes.filter {
                    xorDistance(
                        networkAddress!!.identity.id,
                        it.identity.id
                    ) >= midDist
                })
                if (leftBucket.nodes.isNotEmpty() && rightBucket.nodes.isNotEmpty()) {
                    kbuckets.remove(bucket)
                    kbuckets.add(leftBucket)
                    kbuckets.add(rightBucket)
                    kbuckets.sortBy { it.xorDistanceMin }
                } else {
                    bucket.nodes.removeAt(bucket.nodes.size - 1)
                }
            } else {
                bucket.nodes.removeAt(bucket.nodes.size - 1)
            }
        } else {
            bucket.nodes.add(0, node)
        }
    }

    private fun findNearest(id: SecureHash, number: Int): List<NetworkAddressInfo> {
        val bucket = findBucket(id)
        val sorted = bucket.nodes.sortedBy { xorDistance(id, it.identity.id) }
        return sorted.take(number)
    }

    private fun onNeighbourUpdate(neighbourUpdate: NeighbourUpdate) {
        //log().info("neighbour update")
        networkAddress = neighbourUpdate.localId
        neighbours.clear()
        for (neighbour in neighbourUpdate.addresses) {
            neighbours[neighbour.identity.id] = neighbour
            addToKBuckets(neighbour)
        }
        for (bucket in kbuckets) {
            bucket.nodes.removeIf {
                it.treeAddress.first() != networkAddress!!.treeAddress.first()
            }
        }
    }

    private fun onNeighbourReceivedGreedyMessage(payloadMessage: NeighbourReceivedGreedyMessage) {
        //log().info("received greedy routed message")
        val decrypted = try {
            Ecies.decryptMessage(
                payloadMessage.payload,
                null,
                networkAddress!!.identity.identity.diffieHellmanPublicKey
            ) { x ->
                keyService.getSharedDHSecret(networkAddress!!.identity.id, x)
            }
        } catch (ex: Exception) {
            log().error("Bad message payload")
            return
        }
        val payload = try {
            OneHopMessage.deserializePayload(decrypted)
        } catch (ex: Exception) {
            log().error("bad inner payload")
            return
        }
        val replyRoute = payloadMessage.replyPath
        if (replyRoute.size <= sphinxEncoder.maxRouteLength) {
            routeCache.put(replyRoute.last().id, replyRoute)
        }
        when (payload.javaClass) {
            DhtRequest::class.java -> processDhtRequest(payload as DhtRequest, replyRoute)
            DhtResponse::class.java -> processDhtResponse(payload as DhtResponse)
            else -> log().error("Unknown message type")
        }
    }

    private fun processDhtRequestInternal(request: DhtRequest): DhtResponse {
        val nearest = findBucket(request.key) // query then merge to ensure newscast style
        addToKBuckets(request.sourceAddress)
        for (pushItem in request.push) {
            addToKBuckets(pushItem)
        }
        val response = DhtResponse(request.requestId, nearest.nodes, data[request.key])
        if (request.data != null) {
            data[request.key] = request.data
        }
        return response
    }

    private fun processDhtRequest(request: DhtRequest, replyPath: List<VersionedIdentity>) {
        //log().info("got DhtRequest")
        val response = processDhtRequestInternal(request)
        if (replyPath.size > sphinxEncoder.maxRouteLength) {
            sendGreedyMessage(request.sourceAddress, response)
        } else {
            sendSphinxMessage(replyPath, response)
        }
    }

    private fun processDhtRequest(request: DhtRequest) {
        //log().info("got DhtRequest")
        val response = processDhtRequestInternal(request)
        val knownPath = routeCache.getIfPresent(request.sourceAddress.identity.id)
        if (knownPath == null) {
            sendGreedyMessage(request.sourceAddress, response)
        } else {
            sendSphinxMessage(knownPath, response)
        }
    }

    private fun processDhtResponse(response: DhtResponse) {
        //log().info("got DhtResponse")
        for (node in response.nearestPaths) {
            addToKBuckets(node)
        }
        val originalRequest = outstandingRequests.remove(response.requestId)
        if (originalRequest != null) {
            addToKBuckets(originalRequest.target)
            val replyTime = ChronoUnit.MILLIS.between(originalRequest.sent, Clock.systemUTC().instant())
            requestTimeout = max((requestTimeout + 2L * replyTime) / 2L, ROUTE_CHECK_INTERVAL_MS)
            if (response.data != null) {
                data[originalRequest.request.key] = response.data
            }
        }
    }

    private fun onSphinxRoutedMessage(payloadMessage: SphinxRoutedMessage) {
        //log().info("received sphinx routed message")
        val messageResult = sphinxEncoder.processMessage(
            payloadMessage.messageBytes,
            networkAddress!!.identity.id
        ) { remotePubKey -> keyService.getSharedDHSecret(networkAddress!!.identity.id, remotePubKey) }
        if (messageResult.valid) {
            if (messageResult.finalPayload != null) {
                //log().info("Sphinx message delivered")
                val payload = try {
                    OneHopMessage.deserializePayload(messageResult.finalPayload!!)
                } catch (ex: Exception) {
                    log().error("bad inner payload")
                    return
                }
                when (payload.javaClass) {
                    DhtRequest::class.java -> processDhtRequest(payload as DhtRequest)
                    DhtResponse::class.java -> processDhtResponse(payload as DhtResponse)
                    else -> log().error("Unknown message type")
                }
            } else {
                val forwardMessage = SphinxRoutedMessage(messageResult.forwardMessage!!.messageBytes)
                val wrapper = NeighbourSendSphinxMessage(messageResult.nextNode!!, forwardMessage)
                neighbourLinkActor.tell(wrapper, self)
            }
        } else {
            log().warning("Bad message received")
        }
    }
}
