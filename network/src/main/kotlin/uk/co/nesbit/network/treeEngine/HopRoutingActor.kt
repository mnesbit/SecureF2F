package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import com.github.benmanes.caffeine.cache.Caffeine
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.Ecies
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.SecureHash.Companion.xorDistance
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.Message
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
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlin.experimental.xor
import kotlin.random.Random

enum class MessageWatchTypes {
    ADDRESS_UPDATE,
    CLIENT_DATA_MESSAGES,
    GROUP_MEMBERSHIP_MESSAGES
}

class MessageWatchRequest(val subscription: EnumSet<MessageWatchTypes>)

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

class ClientSendMessage(val destination: SecureHash, val sessionMessage: DataPacket)
class ClientSendResult(val destination: SecureHash, val sent: Boolean)
class ClientReceivedMessage(val source: SecureHash, val sessionMessage: DataPacket)

data class SendGroupManagementMessage(
    val networkDestination: SecureHash,
    val requestId: Int,
    val groupMessage: GroupMembershipMessage
)

data class SendGroupManagementResult(val networkDestination: SecureHash, val requestId: Int, val sent: Boolean)

class HopRoutingActor(
    private val keyService: KeyService,
    private val neighbourLinkActor: ActorRef
) :
    UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            neighbourLinkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, neighbourLinkActor)
        }

        const val SHOW_GAP = true
        const val ROUTE_CHECK_INTERVAL_MS = 5000L
        const val JITTER_MS = ROUTE_CHECK_INTERVAL_MS.toInt() / 2
        const val REQUEST_TIMEOUT_START_MS = 500L
        const val REQUEST_TIMEOUT_INCREMENT_MS = 200L
        const val CLIENT_REQUEST_TIMEOUT_MS = 60000L
        const val GAP_CALC_STABLE = 2
        const val ALPHA = 3
        const val K = 10
        const val TOKEN_RATE = 4.0

        val bestDist = ConcurrentHashMap<SecureHash, Int>()
        val gapZero = AtomicInteger(0)
        val gapStart: Instant = Clock.systemUTC().instant()


        @JvmStatic
        fun xorPrefix(x: SecureHash, y: SecureHash): Int {
            require(x.algorithm == y.algorithm) { "Hashes must be of same type" }
            val xb = x.bytes
            val yb = y.bytes
            for (i in xb.indices) {
                if (xb[i] != yb[i]) {
                    val diff = java.lang.Byte.toUnsignedInt(xb[i] xor yb[i])
                    val diff2 = if (i < xb.size - 1) {
                        java.lang.Byte.toUnsignedInt(xb[i + 1] xor yb[i + 1])
                    } else {
                        0
                    }
                    val prefix16 = (diff shl 8) or diff2
                    val xorx = Integer.numberOfLeadingZeros(prefix16)
                    val shift = 32 - xorx - 3 // shift leading 1 bit right to leave 3 bits
                    return (prefix16 ushr shift)
                }
            }
            return 0
        }

    }

    private class CheckRoutes

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

    private val owners = mutableListOf<Pair<MessageWatchRequest, ActorRef>>()
    private var networkAddress: NetworkAddressInfo? = null
    private val neighbours = mutableMapOf<SecureHash, NetworkAddressInfo>()
    private val sphinxEncoder = Sphinx(keyService.random, 15, 1024)
    private val kbuckets = mutableListOf(KBucket(0, 257))
    private var bucketRefresh: Int = 0
    private var round: Int = 0
    private var tokens: Double = 0.0
    private var tokenRate: Double = TOKEN_RATE
    private var phase: Int = 0
    private var gapNEstimate: Int = 0
    private var gapCalcStable: Int = 0
    private var gapZeroDone = false
    private val outstandingRequests = mutableMapOf<Long, RequestTracker>()
    private val outstandingClientRequests = mutableListOf<ClientRequestState>()
    private var lastSent: Instant = Instant.ofEpochMilli(0L)
    private var requestTimeoutScaled: Long = 8L * REQUEST_TIMEOUT_START_MS
    private var requestTimeoutVarScaled: Long = 0L
    private val localRand = Random(keyService.random.nextLong())
    private val routeCache = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, List<VersionedIdentity>>()
    private val data = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, ByteArray>()
    private val clientCache = Caffeine.newBuilder().maximumSize(20L).build<SecureHash, NetworkAddressInfo>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting HopRoutingActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
            "routeScanningStartup",
            CheckRoutes(),
            localRand.nextInt(ROUTE_CHECK_INTERVAL_MS.toInt()).toLong().millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped HopRoutingActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart HopRoutingActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is CheckRoutes -> onCheckRoutes()
            is MessageWatchRequest -> onWatchRequest(message)
            is Terminated -> onDeath(message)
            is NeighbourUpdate -> onNeighbourUpdate(message)
            is NeighbourReceivedGreedyMessage -> onNeighbourReceivedGreedyMessage(message)
            is SphinxRoutedMessage -> onSphinxRoutedMessage(message)
            is ClientDhtRequest -> onClientRequest(message)
            is ClientSendMessage -> onClientSendMessage(message)
            is SendGroupManagementMessage -> onSendGroupManagementMessage(message)
            else -> throw IllegalArgumentException("Unknown message type ${message.javaClass.name}")
        }
    }

    private fun sendToOwners(message: Any, type: MessageWatchTypes) {
        for (owner in owners) {
            if (owner.first.subscription.contains(type)) {
                owner.second.tell(message, self)
            }
        }
    }

    private fun onWatchRequest(message: MessageWatchRequest) {
        //log().info("WatchRequest from $sender")
        if (owners.none { it.second == sender }) {
            owners += Pair(message, sender)
            context.watch(sender)
            if (message.subscription.contains(MessageWatchTypes.ADDRESS_UPDATE)
                && networkAddress != null
            ) {
                sender.tell(networkAddress, self)
            }
        }
    }

    private fun onDeath(message: Terminated) {
        owners.removeIf { it.second == message.actor }
    }

    private fun onCheckRoutes() {
        timers.startSingleTimer(
            "routeScanningPoller",
            CheckRoutes(),
            (ROUTE_CHECK_INTERVAL_MS + localRand.nextInt(JITTER_MS) - (JITTER_MS / 2)).millis()
        )
        if (networkAddress == null) {
            return
        }
        val distMin = if (SHOW_GAP) calcNearestNodeGap() else 0
        val now = Clock.systemUTC().instant()
        expireRequests(now)
        for (neighbour in neighbours.values) {
            neighbours[neighbour.identity.id] = neighbour
            addToKBuckets(neighbour)
        }
        tokens += tokenRate
        if (neighbours.isNotEmpty()
            && outstandingRequests.size < (ALPHA + 1)
            && tokens >= 0
        ) {
            val nearest = findNearest(networkAddress!!.identity.id, ALPHA)
            ++round
            if (SHOW_GAP) {
                logNearestNodeGap(nearest, distMin)
            }
            tokens = 0.0
            if (nearest.isNotEmpty()) {
                if (phase < nearest.size) {
                    pollChosenNode(nearest[phase], now)
                    ++phase
                } else if (phase < ALPHA) {
                    val neighboursList = neighbours.values.toList()
                    pollChosenNode(neighboursList[localRand.nextInt(neighbours.size)], now)
                    ++phase
                } else {
                    pollRandomNode(now)
                    phase = 0
                }
            } else {
                val neighboursList = neighbours.values.toList()
                pollChosenNode(neighboursList[localRand.nextInt(neighbours.size)], now)
            }
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
                val bucket = findBucket(request.value.request.key)
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
        val clientRequestItr = outstandingClientRequests.iterator()
        while (clientRequestItr.hasNext()) {
            val clientRequest = clientRequestItr.next()
            if (ChronoUnit.MILLIS.between(clientRequest.sendTime, now) > CLIENT_REQUEST_TIMEOUT_MS) {
                clientRequestItr.remove()
                log().info("Timeout expired client request to ${clientRequest.request.key}")
                clientRequest.sender.tell(
                    ClientDhtResponse(
                        clientRequest.request.key,
                        false,
                        clientRequest.request.data
                    ), self
                )
            }
        }
    }

    private fun expireClientRequest(request: RequestTracker, now: Instant) {
        val parent = request.parent
        if (parent == null
            || !outstandingClientRequests.contains(parent)
        ) {
            return
        }
        parent.failed += 1
        log().info("Retry expired client request to  ${request.target} for ${parent.request.key}")
        sendDhtRequest(parent, request.target, parent.request.key, parent.request.data, now)
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
        sendDhtRequest(null, near, networkAddress!!.identity.id, null, now)
    }

    private fun sendDhtRequest(
        parent: ClientRequestState?,
        destination: NetworkAddressInfo,
        key: SecureHash,
        data: ByteArray?,
        now: Instant
    ) {
        val nearestTo = findNearest(destination.identity.id, K)
        var requestId = keyService.random.nextLong()
        if (requestId < 0L) {
            requestId = -requestId
        }
        val request = DhtRequest(
            requestId,
            key,
            networkAddress!!,
            nearestTo,
            data
        )
        val hops = estimateMessageHops(destination)
        tokens -= 2.0 * hops
        val requestTimeout = ((requestTimeoutScaled shr 2) + requestTimeoutVarScaled) shr 1
        val expiryInterval = requestTimeout * hops
        val expiry = now.plusMillis(expiryInterval)
        outstandingRequests[request.requestId] = RequestTracker(request, now, expiry, destination, parent)
        if (parent != null) {
            log().info("Send client DhtRequest to ${destination.identity.id} for $key")
        }
        sendGreedyMessage(destination, request)
    }

    private fun logNearestNodeGap(
        nearest: List<NetworkAddressInfo>,
        distMin: Int
    ) {
        if ((gapCalcStable >= GAP_CALC_STABLE) && nearest.isNotEmpty()) {
            val gap = nearest.map { xorDistance(it.identity.id, networkAddress!!.identity.id) }.minOrNull()!! - distMin
            if (gap == 0 && !gapZeroDone) {
                gapZero.incrementAndGet()
                gapZeroDone = true
            } else if (gap != 0 && gapZeroDone) {
                gapZero.decrementAndGet()
                gapZeroDone = false
            }
            val time = ChronoUnit.MILLIS.between(gapStart, Clock.systemUTC().instant())
            val gapCount = gapZero.get()
            val rate = ((gapCount * 1000L) / time)
            log().info("gap $gap $round ${(100 * gapCount) / gapNEstimate} $rate per/sec ${kbuckets.sumOf { it.nodes.size }} ${kbuckets.size}")
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

    private fun findBucket(id: SecureHash): KBucket {
        val dist = xorDistance(networkAddress!!.identity.id, id)
        return kbuckets.first { it.xorDistanceMin <= dist && dist < it.xorDistanceMax }
    }

    private fun addToKBuckets(node: NetworkAddressInfo) {
        if (networkAddress!!.roots
                .zip(node.roots)
                .count { x -> x.first == x.second } < 2
        ) {
            clientCache.invalidate(node.identity.id)
            return
        }
        if (node.identity.id == networkAddress?.identity?.id) {
            return
        }
        val clientCachedAddress = clientCache.getIfPresent(node.identity.id)
        if (clientCachedAddress != null
            && clientCachedAddress.identity.currentVersion.version < node.identity.currentVersion.version
        ) {
            clientCache.put(node.identity.id, node)
        }
        val bucket = findBucket(node.identity.id)
        val current = bucket.nodes.firstOrNull { it.identity.id == node.identity.id }
        if (current != null
            && current.identity.currentVersion.version > node.identity.currentVersion.version
        ) {
            return
        }
        bucket.nodes.removeIf { it.identity.id == node.identity.id }
        val prefix = xorPrefix(node.identity.id, networkAddress!!.identity.id)
        val subBucket = bucket.nodes
            .filter { xorPrefix(it.identity.id, networkAddress!!.identity.id) == prefix }
        if (subBucket.size >= K) { // we store 'sub-buckets' like KAD to enhance hop gain per query
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
                    dropNode(bucket, subBucket)
                }
            } else {
                dropNode(bucket, subBucket)
            }
        } else {
            bucket.nodes.add(0, node)
        }
    }

    private fun dropNode(bucket: KBucket, subBucket: List<NetworkAddressInfo>) {
        val lastUncached = subBucket.findLast { routeCache.getIfPresent(it.identity.id) == null }
        if (lastUncached != null) {
            bucket.nodes.remove(lastUncached)
        } else {
            bucket.nodes.remove(subBucket.last())
        }
    }

    private fun findNearest(id: SecureHash, number: Int): List<NetworkAddressInfo> {
        val bucket = findBucket(id)
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
                networkAddress!!.roots
                    .zip(it.roots)
                    .count { x -> x.first == x.second } < 2
            }
        }
        tokens = 0.0
        tokenRate = TOKEN_RATE
        clientCache.invalidateAll()
        var index = 1
        while (index < kbuckets.size) {
            val bucket = kbuckets[index]
            if (bucket.nodes.isEmpty()) {
                val prevBucket = kbuckets[index - 1]
                val mergedBucket = KBucket(prevBucket.xorDistanceMin, bucket.xorDistanceMax)
                mergedBucket.nodes.addAll(prevBucket.nodes)
                kbuckets[index - 1] = mergedBucket
                kbuckets.removeAt(index)
            } else {
                ++index
            }
        }
        sendToOwners(neighbourUpdate.localId, MessageWatchTypes.ADDRESS_UPDATE)
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
            DhtRequest::class.java -> processDhtRequest(payload as DhtRequest)
            DhtResponse::class.java -> processDhtResponse(payload as DhtResponse)
            ClientDataMessage::class.java -> processClientDataMessage(payload as ClientDataMessage)
            GroupMembershipMessage::class.java -> processGroupManagementMessage(payload as GroupMembershipMessage)
            else -> log().error("Unknown message type ${payload.javaClass.name}")
        }
    }

    private fun processDhtRequestInternal(request: DhtRequest): DhtResponse {
        val nearest = findNearest(request.key, K) // query then merge to ensure newscast style
        addToKBuckets(request.sourceAddress)
        for (pushItem in request.push) {
            addToKBuckets(pushItem)
        }
        val response = DhtResponse(request.requestId, nearest, data.getIfPresent(request.key))
        if (request.data != null) {
            data.put(request.key, request.data)
        }
        return response
    }

    private fun processDhtRequest(request: DhtRequest) {
        //log().info("got DhtRequest")
        val response = processDhtRequestInternal(request)
        sendGreedyMessage(request.sourceAddress, response)
    }

    private fun estimateMessageHops(target: NetworkAddressInfo): Int {
        val directRoute = routeCache.getIfPresent(target.identity.id)
        if (directRoute != null) {
            return directRoute.size
        } else {
            if (networkAddress == null) {
                return 1
            }
            if (neighbours.containsKey(target.identity.id)) {
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
            routeCache.getIfPresent(originalRequest.target.identity.id)
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
            || !outstandingClientRequests.contains(parent)
        ) {
            return
        }
        val now = Clock.systemUTC().instant()
        parent.responses += 1
        if (parent.request.data == null) { // read
            if (response.data != null) {
                outstandingClientRequests -= parent
                log().info("Client request returned data for ${parent.request.key}")
                clientCache.put(originalRequest.target.identity.id, originalRequest.target)
                parent.sender.tell(ClientDhtResponse(parent.request.key, true, response.data), self)
            } else if (originalRequest.target.identity.id == parent.request.key) {
                clientCache.put(originalRequest.target.identity.id, originalRequest.target)
                outstandingClientRequests -= parent
                log().info("Client request found path to exact node")
                parent.sender.tell(ClientDhtResponse(parent.request.key, true, null), self)
            } else {
                log().info("Client request of key ${parent.request.key} replied from ${originalRequest.target.identity.id}")
                extraClientQueries(parent, now)
            }
        } else { // write
            log().info("Client request of key ${parent.request.key} replied from ${originalRequest.target.identity.id}")
            extraClientQueries(parent, now)
        }
    }

    private fun extraClientQueries(parent: ClientRequestState, now: Instant) {
        val possibleProbes = findNearest(parent.request.key, ALPHA).toMutableList()
        possibleProbes.removeIf {
            it.identity.id in parent.probes
        }
        log().info("Client request for ${parent.request.key} returned ${possibleProbes.size} new targets")
        if (possibleProbes.isNotEmpty()) {
            for (probe in possibleProbes) {
                parent.probes += probe.identity.id
                sendDhtRequest(parent, probe, parent.request.key, parent.request.data, now)
            }
            return
        } else {
            val bucket = findBucket(parent.request.key)
            val alternates = bucket.nodes.toMutableList()
            alternates.removeIf {
                it.identity.id in parent.probes
            }
            if (alternates.isNotEmpty()) {
                val randProbe = alternates[localRand.nextInt(alternates.size)]
                sendDhtRequest(parent, randProbe, parent.request.key, parent.request.data, now)
                return
            }
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
                    ClientDataMessage::class.java -> processClientDataMessage(payload as ClientDataMessage)
                    GroupMembershipMessage::class.java -> processGroupManagementMessage(payload as GroupMembershipMessage)
                    else -> log().error("Unknown message type ${payload.javaClass.name}")
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

    private fun onClientSendMessage(message: ClientSendMessage) {
        if (networkAddress == null) {
            log().warning("Node not ready for client data")
            sender.tell(ClientSendResult(message.destination, false), self)
            return
        }
        val clientDataMessage = ClientDataMessage(
            networkAddress!!,
            message.sessionMessage.sessionId,
            message.sessionMessage.seqNo,
            message.sessionMessage.ackSeqNo,
            message.sessionMessage.selectiveAck,
            message.sessionMessage.receiveWindowSize,
            message.sessionMessage.payload
        )
        val cachedAddress = clientCache.getIfPresent(message.destination)
        val knownPath = routeCache.getIfPresent(message.destination)
        if (knownPath == null) {
            if (cachedAddress != null) {
                sendGreedyMessage(cachedAddress, clientDataMessage)
            } else {
                val bucket = findBucket(message.destination)
                val destinationAddress = bucket.nodes.firstOrNull { it.identity.id == message.destination }
                if (destinationAddress == null) {
                    log().warning("Node not known ${message.destination}")
                    sender.tell(ClientSendResult(message.destination, false), self)
                    return
                }
                clientCache.put(destinationAddress.identity.id, destinationAddress)
                sendGreedyMessage(destinationAddress, clientDataMessage)
            }
        } else {
            sendSphinxMessage(knownPath, clientDataMessage)
        }
        sender.tell(ClientSendResult(message.destination, true), self)
    }

    private fun onSendGroupManagementMessage(message: SendGroupManagementMessage) {
        if (networkAddress == null) {
            log().warning("Node not ready for group management")
            sender.tell(SendGroupManagementResult(message.networkDestination, message.requestId, false), self)
            return
        }
        val cachedAddress = clientCache.getIfPresent(message.networkDestination)
        val knownPath = routeCache.getIfPresent(message.networkDestination)
        if (knownPath == null) {
            if (cachedAddress != null) {
                sendGreedyMessage(cachedAddress, message.groupMessage)
            } else {
                val bucket = findBucket(message.networkDestination)
                val destinationAddress = bucket.nodes.firstOrNull { it.identity.id == message.networkDestination }
                if (destinationAddress == null) {
                    log().warning("Node not known ${message.networkDestination}")
                    sender.tell(SendGroupManagementResult(message.networkDestination, message.requestId, false), self)
                    return
                }
                clientCache.put(destinationAddress.identity.id, destinationAddress)
                sendGreedyMessage(destinationAddress, message.groupMessage)
            }
        } else {
            sendSphinxMessage(knownPath, message.groupMessage)
        }
        sender.tell(SendGroupManagementResult(message.networkDestination, message.requestId, true), self)
    }

    private fun processClientDataMessage(clientDataMessage: ClientDataMessage) {
        clientCache.put(clientDataMessage.source.identity.id, clientDataMessage.source)
        routeCache.getIfPresent(clientDataMessage.source.identity.id)
        val sessionMessage = DataPacket(
            clientDataMessage.sessionId,
            clientDataMessage.seqNo,
            clientDataMessage.ackSeqNo,
            clientDataMessage.selectiveAck,
            clientDataMessage.receiveWindowSize,
            clientDataMessage.payload
        )
        val receivedMessage = ClientReceivedMessage(clientDataMessage.source.identity.id, sessionMessage)
        sendToOwners(receivedMessage, MessageWatchTypes.CLIENT_DATA_MESSAGES)
    }

    private fun processGroupManagementMessage(groupMessage: GroupMembershipMessage) {
        sendToOwners(groupMessage, MessageWatchTypes.GROUP_MEMBERSHIP_MESSAGES)
    }

}
