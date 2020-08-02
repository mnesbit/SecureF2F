package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import com.github.benmanes.caffeine.cache.Caffeine
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.Ecies
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.SecureHash.Companion.xorDistance
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
import uk.co.nesbit.utils.printHexBinary
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.random.Random

class ClientDhtRequest(
        val key: SecureHash,
        val data: ByteArray?
) {
    override fun toString(): String {
        return "ClientDhtRequest($key, ${data?.printHexBinary()})"
    }
}

class ClientDhtResponse(
        val key: SecureHash,
        val success: Boolean,
        val data: ByteArray?
) {
    override fun toString(): String {
        return "ClientDhtResponse($key, $success, ${data?.printHexBinary()})"
    }
}

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

        const val REFRESH_INTERVAL = 20000L
        const val JITTER_MS = 1000
        const val ROUTE_CHECK_INTERVAL_MS = REFRESH_INTERVAL / 4L
        const val REQUEST_TIMEOUT_START_MS = 500L
        const val REQUEST_TIMEOUT_INCREMENT_MS = 100L
        const val ALPHA = 3
        const val K = 15
    }

    private class CheckRoutes(val first: Boolean)
    private class KBucket(
            val xorDistanceMin: Int, // inclusive
            val xorDistanceMax: Int // exclusive
    ) {
        val nodes: MutableList<NetworkAddressInfo> = mutableListOf()
    }

    private class RequestTracker(
            val request: DhtRequest,
            val sent: Instant,
            val expire: Instant,
            val target: NetworkAddressInfo,
            val parent: ClientRequestState?
    )

    private class ClientRequestState(
            val sendTime: Instant,
            val sender: ActorRef,
            val request: ClientDhtRequest,
            val probes: MutableSet<SecureHash> = mutableSetOf(),
            var failed: Int = 0,
            var responses: Int = 0
    )

    private val owners = mutableSetOf<ActorRef>()
    private var networkAddress: NetworkAddressInfo? = null
    private val neighbours = mutableMapOf<SecureHash, NetworkAddressInfo>()
    private val sphinxEncoder = Sphinx(keyService.random, 15, 1024)
    private val kbuckets = mutableListOf(KBucket(0, 257))
    private var bucketRefresh: Int = 0
    private val outstandingRequests = mutableMapOf<Long, RequestTracker>()
    private val outstandingClientRequests = mutableListOf<ClientRequestState>()
    private var lastSent: Instant = Instant.ofEpochMilli(0L)
    private var requestTimeoutScaled: Long = 8L * REQUEST_TIMEOUT_START_MS
    private var requestTimeoutVarScaled: Long = 0L
    private val localRand = Random(keyService.random.nextLong())
    private val routeCache = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, List<VersionedIdentity>>()
    private val data = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, ByteArray>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting NeighbourLinkActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
                "routeScanningStartup",
                CheckRoutes(true),
                localRand.nextInt(ROUTE_CHECK_INTERVAL_MS.toInt()).toLong().millis()
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
            is CheckRoutes -> onCheckRoutes()
            is WatchRequest -> onWatchRequest()
            is NeighbourUpdate -> onNeighbourUpdate(message)
            is NeighbourReceivedGreedyMessage -> onNeighbourReceivedGreedyMessage(message)
            is SphinxRoutedMessage -> onSphinxRoutedMessage(message)
            is ClientDhtRequest -> onClientRequest(message)
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

    private fun onCheckRoutes() {
        timers.startSingleTimer(
                "routeScanningPoller",
                CheckRoutes(false),
                (ROUTE_CHECK_INTERVAL_MS + localRand.nextInt(JITTER_MS) - (JITTER_MS / 2)).millis()
        )
        if (networkAddress == null) {
            return
        }
        val now = Clock.systemUTC().instant()
        expireRequests(now)
        for (neighbour in neighbours.values) {
            neighbours[neighbour.identity.id] = neighbour
            addToKBuckets(neighbour)
        }
        if (outstandingRequests.isEmpty()
                && ChronoUnit.MILLIS.between(lastSent, now) >= REFRESH_INTERVAL) {
            val nearest = findNearest(networkAddress!!.identity.id, ALPHA)

            for (near in nearest) {
                pollChosenNode(near, now)
            }
            pollRandomNode(now)
            lastSent = now
        }
    }

    private fun expireRequests(now: Instant) {
        val expiredRequests = mutableListOf<RequestTracker>()
        val requestItr = outstandingRequests.iterator()
        while (requestItr.hasNext()) {
            val request = requestItr.next()
            if (request.value.expire < now) {
                expiredRequests += request.value
                //log().info("stale request")
                requestItr.remove()
                val bucket = findBucket(request.value.request.key, false)
                if (bucket.nodes.remove(request.value.target)) { // move to end
                    bucket.nodes.add(request.value.target)
                }
                routeCache.invalidate(request.value.target.identity.id) // don't trust sphinx route
                requestTimeoutScaled += REQUEST_TIMEOUT_INCREMENT_MS shl 3
            }
        }
        for (expired in expiredRequests) {
            expireClientRequest(expired, now)
        }
    }

    private fun expireClientRequest(request: RequestTracker, now: Instant) {
        val parent = request.parent
        if (parent == null
                || !outstandingClientRequests.contains(parent)) {
            return
        }
        log().warning("expire client request to ${request.target} for ${parent.request.key}")
        parent.failed += 1
        if (parent.failed > ALPHA) {
            parent.responses += 1
            if (parent.responses >= parent.probes.size) {
                log().warning("Client request for ${parent.request.key} expired")
                outstandingClientRequests -= parent
                parent.sender.tell(ClientDhtResponse(parent.request.key, false, parent.request.data), self)
            }
        } else {
            log().info("Retry client request to  ${request.target} for ${parent.request.key}")
            sendDhtRequest(parent, request.target, parent.request.key, parent.request.data, now)
        }
    }

    private fun pollRandomNode(now: Instant) {
        bucketRefresh = bucketRefresh.rem(kbuckets.size)
        val randomBucket = kbuckets[bucketRefresh]
        bucketRefresh = (bucketRefresh + 1).rem(kbuckets.size)
        if (randomBucket.nodes.isNotEmpty()) {
            val target = randomBucket.nodes.removeAt(randomBucket.nodes.size - 1)
            pollChosenNode(target, now)
        }
    }

    private fun pollChosenNode(near: NetworkAddressInfo, now: Instant) {
        sendDhtRequest(null, near, networkAddress!!.identity.id, networkAddress!!.serialize(), now)
    }

    private fun sendDhtRequest(parent: ClientRequestState?,
                               destination: NetworkAddressInfo,
                               key: SecureHash,
                               data: ByteArray?,
                               now: Instant) {
        val nearestTo = findBucket(destination.identity.id, true)
        var requestId = keyService.random.nextLong()
        if (requestId < 0L) {
            requestId = -requestId
        }
        val request = DhtRequest(
                requestId,
                key,
                networkAddress!!,
                nearestTo.nodes,
                data
        )
        val hops = estimateMessageHops(destination)
        val requestTimeout = ((requestTimeoutScaled shr 2) + requestTimeoutVarScaled) shr 1
        val expiryInterval = requestTimeout * hops
        val expiry = now.plusMillis(expiryInterval)
        outstandingRequests[request.requestId] = RequestTracker(request, now, expiry, destination, parent)
        if (parent != null) {
            log().info("Send client DhtRequest to ${destination.identity.id} for $key")
        }
        sendGreedyMessage(destination, request)
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
        val wrapper = OneHopMessage.createOneHopMessage(message)
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
        val wrapper = OneHopMessage.createOneHopMessage(message)
        val sphinxMessage = sphinxEncoder.makeMessage(
                replyRoute.map { it.identity },
                wrapper.serialize(),
                keyService.random
        )
        val sphinxRoutedMessage = SphinxRoutedMessage(sphinxMessage.messageBytes)
        val neighbourSend = NeighbourSendSphinxMessage(replyRoute.first().id, sphinxRoutedMessage)
        neighbourLinkActor.tell(neighbourSend, self)
    }

    private fun findBucket(id: SecureHash, allowMerge: Boolean): KBucket {
        val dist = xorDistance(networkAddress!!.identity.id, id)
        val bucket = kbuckets.first { it.xorDistanceMin <= dist && dist < it.xorDistanceMax }
        if (allowMerge && bucket.nodes.size < K) {
            val allAddresses = kbuckets.flatMap { it.nodes }
            val sorted = allAddresses.sortedBy { xorDistance(it.identity.id, id) }
            val mergedBucket = KBucket(dist, dist)
            mergedBucket.nodes.addAll(sorted.take(K))
            return mergedBucket
        }
        return bucket
    }

    private fun addToKBuckets(node: NetworkAddressInfo) {
        if (node.roots != networkAddress!!.roots) {
            return
        }
        if (node.identity.id == networkAddress?.identity?.id) {
            return
        }
        val bucket = findBucket(node.identity.id, false)
        val current = bucket.nodes.firstOrNull { it.identity.id == node.identity.id }
        if (current != null
                && current.identity.currentVersion.version > node.identity.currentVersion.version
        ) {
            return
        }
        bucket.nodes.removeIf { it.identity.id == node.identity.id }
        if (bucket.nodes.size >= K) {
            bucket.nodes.add(0, node)
            if (bucket.xorDistanceMax - bucket.xorDistanceMin > 1) {
                val sorted = bucket.nodes.sortedBy {
                    xorDistance(networkAddress!!.identity.id, it.identity.id)
                }
                val mid = sorted[sorted.size / 2]
                val midDist = xorDistance(networkAddress!!.identity.id, mid.identity.id)
                val (left, right) = bucket.nodes.partition {
                    xorDistance(
                            networkAddress!!.identity.id,
                            it.identity.id
                    ) < midDist
                }
                if (left.isNotEmpty() && right.isNotEmpty()) {
                    kbuckets.remove(bucket)
                    val leftBucket = KBucket(bucket.xorDistanceMin, midDist)
                    leftBucket.nodes.addAll(left)
                    kbuckets.add(leftBucket)
                    val rightBucket = KBucket(midDist, bucket.xorDistanceMax)
                    rightBucket.nodes.addAll(right)
                    kbuckets.add(rightBucket)
                    kbuckets.sortBy { it.xorDistanceMin }
                } else {
                    dropNode(bucket)
                }
            } else {
                dropNode(bucket)
            }
        } else {
            bucket.nodes.add(0, node)
        }
    }

    private fun dropNode(bucket: KBucket) {
        val lastUncached = bucket.nodes.findLast { routeCache.getIfPresent(it.identity.id) == null }
        if (lastUncached != null) {
            bucket.nodes.remove(lastUncached)
        } else {
            bucket.nodes.removeAt(bucket.nodes.size - 1)
        }
    }

    private fun findNearest(id: SecureHash, number: Int): List<NetworkAddressInfo> {
        val bucket = findBucket(id, true)
        val sorted = bucket.nodes.sortedBy { xorDistance(id, it.identity.id) }
        return sorted.take(number)
    }

    private fun onNeighbourUpdate(neighbourUpdate: NeighbourUpdate) {
        networkAddress = neighbourUpdate.localId
        neighbours.clear()
        for (neighbour in neighbourUpdate.addresses) {
            neighbours[neighbour.identity.id] = neighbour
            addToKBuckets(neighbour)
        }
        //log().info("neighbour update with root ${networkAddress!!.roots}")
        for (bucket in kbuckets) {
            bucket.nodes.removeIf {
                it.roots != networkAddress!!.roots
            }
        }
    }

    private fun onNeighbourReceivedGreedyMessage(payloadMessage: NeighbourReceivedGreedyMessage) {
        //log().info("received greedy routed message")
        if (networkAddress == null) {
            return
        }
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
        val nearest = findBucket(request.key, true) // query then merge to ensure newscast style
        addToKBuckets(request.sourceAddress)
        for (pushItem in request.push) {
            addToKBuckets(pushItem)
        }
        val response = DhtResponse(request.requestId, nearest.nodes, data.getIfPresent(request.key))
        if (request.data != null) {
            data.put(request.key, request.data)
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

    private fun estimateMessageHops(target: NetworkAddressInfo): Int {
        val directRoute = routeCache.getIfPresent(target.identity.id)
        if (directRoute != null) {
            return directRoute.size
        } else {
            if (networkAddress == null) {
                return 1
            }
            return networkAddress!!.greedyDist(target).coerceAtMost(sphinxEncoder.maxRouteLength)
        }
    }

    private fun processDhtResponse(response: DhtResponse) {
        //log().info("got DhtResponse")
        val originalRequest = outstandingRequests.remove(response.requestId)
        if (originalRequest != null) {
            addToKBuckets(originalRequest.target)
        }
        for (node in response.nearestPaths) {
            addToKBuckets(node)
        }
        if (originalRequest != null) {
            updateTimeoutEstimate(originalRequest)
            if (response.data != null) {
                data.put(originalRequest.request.key, response.data)
            }
            processResponseForClient(originalRequest, response)
        } else {
            requestTimeoutScaled += REQUEST_TIMEOUT_INCREMENT_MS shl 3
        }
    }

    private fun processResponseForClient(originalRequest: RequestTracker, response: DhtResponse) {
        val parent = originalRequest.parent
        if (parent == null
                || !outstandingClientRequests.contains(parent)) {
            return
        }
        val now = Clock.systemUTC().instant()
        parent.responses += 1
        if (parent.request.data == null) { // read
            if (response.data != null) {
                outstandingClientRequests -= parent
                log().info("Client request reyurned data for ${parent.request.key}")
                parent.sender.tell(ClientDhtResponse(parent.request.key, true, response.data), self)
            } else {
                extraClientQueries(parent, now)
            }
        } else { // write
            extraClientQueries(parent, now)
        }
    }

    private fun extraClientQueries(parent: ClientRequestState, now: Instant) {
        val possibleProbes = findNearest(parent.request.key, ALPHA).toMutableList()
        possibleProbes.removeIf {
            it.identity.id in parent.probes
        }
        if (possibleProbes.isNotEmpty()) {
            for (probe in possibleProbes) {
                parent.probes += probe.identity.id
                sendDhtRequest(parent, probe, parent.request.key, parent.request.data, now)
            }
            return
        }
        if (parent.responses >= parent.probes.size) {
            log().warning("Client request for ${parent.request.key} expired")
            outstandingClientRequests -= parent
            val success = (parent.request.data != null)
            parent.sender.tell(ClientDhtResponse(parent.request.key, success, parent.request.data), self)
        }
    }

    private fun updateTimeoutEstimate(originalRequest: RequestTracker) {
        val hops = originalRequest.target.greedyDist(networkAddress!!)
        val replyTime = ChronoUnit.MILLIS.between(originalRequest.sent, Clock.systemUTC().instant())
        val replyTimePerHop = replyTime / hops
        // Van Jacobson Algorithm for RTT
        if (requestTimeoutVarScaled == 0L) {
            requestTimeoutScaled = replyTimePerHop shl 3
            requestTimeoutVarScaled = replyTimePerHop shl 1
        } else {
            var replyTimeError = replyTimePerHop - (requestTimeoutScaled shr 3)
            requestTimeoutScaled += replyTimeError
            if (replyTimeError < 0) {
                replyTimeError = -replyTimeError
            }
            replyTimeError -= (requestTimeoutVarScaled shr 2)
            requestTimeoutVarScaled += replyTimeError
        }
    }

    private fun onSphinxRoutedMessage(payloadMessage: SphinxRoutedMessage) {
        if (networkAddress == null) {
            return
        }
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

    private fun onClientRequest(request: ClientDhtRequest) {
        log().info("onClientRequest ${request.key} ${request.data?.printHexBinary()}")
        if (request.data == null) { // read
            val localData = data.getIfPresent(request.key)
            if (localData != null) { // already have cached answer
                log().info("Satisfy client get of ${request.key} with local data ")
                sender.tell(ClientDhtResponse(request.key, true, localData), self)
                return
            }
        } else { // write
            data.put(request.key, request.data)
        }
        if (networkAddress == null) {
            log().warning("Node not ready for client key ${request.key}")
            sender.tell(ClientDhtResponse(request.key, false, request.data), self)
            return
        }
        val now = Clock.systemUTC().instant()
        val initialProbes = findNearest(request.key, ALPHA)
        if (initialProbes.isEmpty()) {
            log().warning("No nearest nodes for client key ${request.key}")
            sender.tell(ClientDhtResponse(request.key, false, request.data), self)
            return
        }
        val requestState = ClientRequestState(now, sender, request)
        outstandingClientRequests += requestState
        for (probe in initialProbes) {
            requestState.probes += probe.identity.id
            sendDhtRequest(requestState, probe, request.key, request.data, now)
        }
    }
}
