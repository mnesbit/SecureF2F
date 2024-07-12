package uk.co.nesbit.network.treeEngine

import com.github.benmanes.caffeine.cache.Caffeine
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.*
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.simpleactor.*
import uk.co.nesbit.utils.printHexBinary
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.random.Random

enum class MessageWatchTypes {
    ADDRESS_UPDATE,
    CLIENT_DATA_MESSAGES,
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

class HopRoutingActor(
    private val keyService: KeyService,
    private val neighbourLinkActor: ActorRef
) :
    AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            neighbourLinkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, neighbourLinkActor)
        }

        const val ROUTE_CHECK_INTERVAL_MS = 5000L
        const val JITTER_MS = ROUTE_CHECK_INTERVAL_MS.toInt() / 2
        const val REQUEST_TIMEOUT_START_MS = 500L
        const val CLIENT_REQUEST_TIMEOUT_MS = 60000L
        const val ALPHA = 3
        const val MAX_PEERS = 256
    }

    private class CheckRoutes

    private class RequestTracker(
        val request: DhtRequest,
        val sent: Instant,
        val expire: Instant,
        val target: NetworkAddressInfo,
        val parent: ClientRequestState?
    ) {
        var active: Boolean = true
    }

    private class ClientRequestState(
        val sendTime: Instant,
        val sender: ActorRef,
        val request: ClientDhtRequest,
        val probes: MutableSet<SecureHash> = mutableSetOf(),
        var failed: Int = 0,
        var responses: Int = 0
    )

    private class RingAddress(
        val address: NetworkAddressInfo,
        ring: Int
    ) {
        companion object {
            fun ringHash(id: SecureHash, ring: Int): SecureHash {
                return SecureHash.secureHash(concatByteArrays(id.serialize(), ring.toByteArray()))
            }
        }

        val hash: SecureHash by lazy {
            ringHash(address.identity.id, ring)
        }
    }

    private val owners = mutableListOf<Pair<MessageWatchRequest, ActorRef>>()
    private var networkAddress: NetworkAddressInfo? = null
    private val neighbours = mutableMapOf<SecureHash, NetworkAddressInfo>()
    private val sphinxEncoder = Sphinx(keyService.random, 15, 1024)
    private val peers = LinkedHashMap<SecureHash, NetworkAddressInfo>()
    private var round: Int = 0
    private var phase: Int = 0
    private var prevPhase: Int = 0
    private var refresh: Int = 0
    private var tokens: Double = 0.0
    private var tokenRate: Double = 1.0
    private val outstandingRequests = mutableMapOf<Long, RequestTracker>()
    private val outstandingClientRequests = mutableListOf<ClientRequestState>()
    private var lastTokenRefresh: Instant = Clock.systemUTC().instant()
    private var greedyRTT = TimeoutEstimator(REQUEST_TIMEOUT_START_MS)
    private var sphinxRTT = TimeoutEstimator(REQUEST_TIMEOUT_START_MS)
    private val localRand = Random(keyService.random.nextLong())
    private val routeCache = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, List<VersionedIdentity>>()
    private val data = Caffeine.newBuilder().maximumSize(100L).build<SecureHash, ByteArray>()
    private val clientCache = Caffeine.newBuilder().maximumSize(20L).build<SecureHash, NetworkAddressInfo>()
    private val rings = Array<List<RingAddress>?>(ALPHA) { null }

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
            val address = networkAddress
            if (message.subscription.contains(MessageWatchTypes.ADDRESS_UPDATE)
                && address != null
            ) {
                sender.tell(address, self)
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
        val now = Clock.systemUTC().instant()
        expireRequests(now)
        for (neighbour in neighbours.values) {
            neighbours[neighbour.identity.id] = neighbour
            updatePeers(neighbour)
        }
        refreshTokens(now)
        if (neighbours.isNotEmpty()
            && outstandingRequests.count { it.value.active } < (ALPHA + 1)
            && tokens >= 0
        ) {
            ++round
            tokens = 0.0
            log().debug { "round $round ${peers.size}" }
            val next = nextPeers(networkAddress!!.identity.id, ALPHA).toList()
            if (phase < next.size) {
                val target = next[phase]
                pollChosenNode(target, now)
                ++phase
            } else {
                val prev = prevPeer(networkAddress!!.identity.id, prevPhase)
                if (prev != null) {
                    pollChosenNode(prev, now)
                    prevPhase = (prevPhase + 1).rem(ALPHA)
                } else {
                    val neighbourList = neighbours.values.toList()
                    refresh = refresh.rem(neighbourList.size)
                    val target = neighbourList[refresh]
                    refresh = (refresh + 1).rem(neighbourList.size)
                    pollChosenNode(target, now)
                }
                phase = 0
            }
        }
    }

    private fun refreshTokens(now: Instant) {
        val interval = ChronoUnit.MILLIS.between(lastTokenRefresh, now)
        val timeout = getTimeoutEstimate(true)
        val tokenRateEstimate = (interval / timeout).toDouble() / (ALPHA + 1).toDouble()
        tokenRate = 0.9 * tokenRate + 0.1 * tokenRateEstimate
        tokens += tokenRate
        lastTokenRefresh = now
    }

    private fun expireRequests(now: Instant) {
        val expiredRequests = mutableListOf<RequestTracker>()
        val requestItr = outstandingRequests.iterator()
        while (requestItr.hasNext()) {
            val request = requestItr.next()
            if (!request.value.active) {
                requestItr.remove()
            } else if (request.value.expire < now) {
                request.value.active = false // leave record longer in case we can improve RTT
                expiredRequests += request.value
                //log().info("stale request")
                if (request.value.target.roots == networkAddress!!.roots) { // unless possibly stale
                    peers.remove(request.value.target.identity.id)
                    rings.fill(null)
                }
                clientCache.invalidate(request.value.target.identity.id)
                routeCache.invalidate(request.value.target.identity.id) // don't trust sphinx route
            }
        }
        for (expired in expiredRequests) {
            expireClientRequest(expired)
        }
        val clientRequestItr = outstandingClientRequests.iterator()
        while (clientRequestItr.hasNext()) {
            val clientRequest = clientRequestItr.next()
            if (ChronoUnit.MILLIS.between(clientRequest.sendTime, now) > CLIENT_REQUEST_TIMEOUT_MS) {
                clientRequestItr.remove()
                log().info("Timeout expired Client request for ${clientRequest.request.key} replies ${clientRequest.responses} failed ${clientRequest.failed} sent ${clientRequest.probes.size}")
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

    private fun expireClientRequest(request: RequestTracker) {
        val parent = request.parent
        if (parent == null
            || !outstandingClientRequests.contains(parent)
        ) {
            return
        }
        parent.failed += 1
        log().info("Expired client request to ${request.target} for ${parent.request.key}")
        if (parent.responses + parent.failed >= parent.probes.size) {
            log().info("Client request for ${parent.request.key} expired replies ${parent.responses} failed ${parent.failed} sent ${parent.probes.size}")
            outstandingClientRequests -= parent
            val success = (parent.request.data != null)
            parent.sender.tell(ClientDhtResponse(parent.request.key, success, parent.request.data), self)
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
        val next = nextPeers(destination.identity.id, 3 * ALPHA)
        val nearest = findNearest(destination.identity.id, 2 * ALPHA)
        var requestId = keyService.random.nextLong()
        if (requestId < 0L) {
            requestId = -requestId
        }
        val request = DhtRequest(
            requestId,
            key,
            networkAddress!!,
            (next + nearest).toList(),
            data
        )
        val hops = estimateMessageHops(destination)
        tokens -= 2.0 * hops
        val requestTimeout = getTimeoutEstimate(routeCache.getIfPresent(destination.identity.id) == null)
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
            routeCache.put(destination.identity.id, cachedPrivateRoute)
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

    private fun shuffledPeerList(ring: Int): List<RingAddress> {
        val cached = rings[ring]
        if (cached != null) {
            return cached
        }
        val peerList = peers.values.map { RingAddress(it, ring) }.toMutableList()
        peerList += RingAddress(networkAddress!!, ring)
        peerList.sortBy { it.hash }
        rings[ring] = peerList
        return peerList
    }

    private fun nextPeers(node: SecureHash, count: Int): Set<NetworkAddressInfo> {
        if (peers.size <= count) {
            return peers.values.toSet()
        }
        val nearest = mutableSetOf<NetworkAddressInfo>()
        val rings = mutableListOf<List<RingAddress>>()
        val ringIndices = IntArray(ALPHA)
        for (ring in 0 until ALPHA) {
            val peers = shuffledPeerList(ring)
            rings += peers
            val target = RingAddress.ringHash(node, ring)
            val next = peers.indexOfFirst { address ->
                target < address.hash
            }
            val index = if (next > 0) next else 0
            nearest += peers[index].address
            ringIndices[ring] = index
        }
        var ring = 0
        while (nearest.size < count) {
            val peers = rings[ring]
            val index = if (ringIndices[ring] < peers.size - 1) ringIndices[ring] + 1 else 0
            nearest += peers[index].address
            ringIndices[ring] = index
            ring = (ring + 1).rem(ALPHA)
        }
        nearest -= networkAddress!!
        return nearest
    }

    private fun prevPeer(node: SecureHash, ring: Int): NetworkAddressInfo? {
        if (peers.isEmpty()) {
            return null
        }
        val peers = shuffledPeerList(ring)
        val target = RingAddress.ringHash(node, ring)
        val next = peers.indexOfFirst { address ->
            target <= address.hash
        }
        val index = if (next > 0) next - 1 else peers.size - 1
        return peers[index].address
    }

    private fun updatePeers(node: NetworkAddressInfo) {
        if (networkAddress!!.roots
                .zip(node.roots)
                .count { x -> x.first == x.second } < 2
        ) {
            clientCache.invalidate(node.identity.id)
            peers.remove(node.identity.id)
            rings.fill(null)
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
        val current = peers[node.identity.id]
        if (current != null
            && current.identity.currentVersion.version > node.identity.currentVersion.version
        ) {
            return
        }
        peers.remove(node.identity.id)
        if (peers.size >= MAX_PEERS) {
            rings.fill(null)
            // LRU didn't work when setting intentionally small sizes.
            // Removing one of the nearest predecessors seems to preserve network function adequately
            val next = findNearest(node.identity.id, ALPHA).toList()
            if (next.isNotEmpty()) {
                peers.remove(next[localRand.nextInt(next.size)].identity.id)
            }
        }
        peers[node.identity.id] = node
        rings.fill(null)
    }

    private fun findNearest(node: SecureHash, count: Int): Set<NetworkAddressInfo> {
        if (peers.size <= count) {
            return peers.values.toSet()
        }
        val nearest = mutableSetOf<NetworkAddressInfo>()
        val rings = mutableListOf<List<RingAddress>>()
        val ringIndices = IntArray(3)
        for (ring in 0 until ALPHA) {
            val peers = shuffledPeerList(ring)
            rings += peers
            val match = peers.indexOfFirst { it.address.identity.id == node }
            if (match == -1) {
                val target = RingAddress.ringHash(node, ring)
                val next = peers.indexOfFirst { address ->
                    target < address.hash
                }
                val index = if (next > 0) next - 1 else peers.size - 1
                nearest += peers[index].address
                ringIndices[ring] = index
            } else {
                nearest += peers[match].address
                ringIndices[ring] = match
            }
        }
        var ring = 0
        while (nearest.size < count) {
            val peers = rings[ring]
            val index = if (ringIndices[ring] > 0) ringIndices[ring] - 1 else peers.size - 1
            nearest += peers[index].address
            ringIndices[ring] = index
            ring = (ring + 1).rem(ALPHA)
        }
        nearest -= networkAddress!!
        return nearest
    }

    private fun findExact(id: SecureHash): NetworkAddressInfo? {
        return peers[id]
    }

    private fun onNeighbourUpdate(neighbourUpdate: NeighbourUpdate) {
        networkAddress = neighbourUpdate.localId
        neighbours.clear()
        for (neighbour in neighbourUpdate.addresses) {
            neighbours[neighbour.identity.id] = neighbour
            updatePeers(neighbour)
        }
        val peerItr = peers.iterator()
        while (peerItr.hasNext()) {
            val peer = peerItr.next().value
            if (peer.roots.zip(networkAddress!!.roots).count { it.first == it.second } < 1) {
                peerItr.remove()
                rings.fill(null)
                clientCache.invalidate(peer.identity.id)
                routeCache.invalidate(peer.identity.id)
            }
        }
        //log().info("neighbour update with root ${networkAddress!!.roots}")
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
            DhtResponse::class.java -> processDhtResponse(payload as DhtResponse, true)
            ClientDataMessage::class.java -> processClientDataMessage(payload as ClientDataMessage)
            else -> log().error("Unknown message type ${payload.javaClass.name}")
        }
    }

    private fun processDhtRequestInternal(request: DhtRequest): DhtResponse {
        for (pushItem in request.push) {
            updatePeers(pushItem)
        }
        updatePeers(request.sourceAddress)
        val next = nextPeers(request.key, 2 * ALPHA)
        val nearest = findNearest(request.key, 3 * ALPHA)
        val response =
            DhtResponse(request.requestId, (nearest + next + networkAddress!!).toList(), data.getIfPresent(request.key))
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

    private fun processDhtResponse(response: DhtResponse, greedyRoute: Boolean) {
        //log().info("got DhtResponse")
        val originalRequest = outstandingRequests.remove(response.requestId)
        for (node in response.nearestPaths) {
            updatePeers(node)
        }
        if (originalRequest != null) {
            val route = routeCache.getIfPresent(originalRequest.target.identity.id)
            if (route != null) {
                routeCache.put(originalRequest.target.identity.id, route)
            }
            updateTimeoutEstimate(originalRequest, greedyRoute)
            if (response.data != null) {
                data.put(originalRequest.request.key, response.data)
            }
            processResponseForClient(originalRequest, response)
        } else {
            log().info("DHTResponse, but original request timed out")
            if (greedyRoute) greedyRTT.updateLostPacket() else sphinxRTT.updateLostPacket()
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
                log().info("Client request returned data for ${parent.request.key} from ${originalRequest.target.identity.id}")
                clientCache.put(originalRequest.target.identity.id, originalRequest.target)
                parent.sender.tell(ClientDhtResponse(parent.request.key, true, response.data), self)
            } else if (originalRequest.target.identity.id == parent.request.key) {
                clientCache.put(originalRequest.target.identity.id, originalRequest.target)
                outstandingClientRequests -= parent
                log().info("Client request found path to exact node ${originalRequest.target.identity.id}")
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
        if (possibleProbes.isEmpty()) {
            possibleProbes.addAll(findNearest(parent.request.key, (2 + parent.failed) * ALPHA))
            possibleProbes.removeIf {
                it.identity.id in parent.probes
            }
        }
        log().info("Client request for ${parent.request.key} returned ${possibleProbes.size} new targets after ${parent.probes.size} tried")
        if (possibleProbes.isNotEmpty()) {
            for (probe in possibleProbes) {
                parent.probes += probe.identity.id
                sendDhtRequest(parent, probe, parent.request.key, parent.request.data, now)
            }
            return
        }
        if (parent.responses + parent.failed >= parent.probes.size) {
            log().info("Client request for ${parent.request.key} expired replies ${parent.responses} failed ${parent.failed} sent ${parent.probes.size}")
            outstandingClientRequests -= parent
            val success = (parent.request.data != null)
            parent.sender.tell(ClientDhtResponse(parent.request.key, success, parent.request.data), self)
        }
    }

    private fun updateTimeoutEstimate(originalRequest: RequestTracker, greedyRoute: Boolean) {
        val now = Clock.systemUTC().instant()
        val replyTime = ChronoUnit.MILLIS.between(originalRequest.sent, now)
        val hops = estimateMessageHops(originalRequest.target)
        val replyTimePerHop = replyTime / hops
        if (greedyRoute) {
            greedyRTT.updateRtt(replyTimePerHop)
        } else {
            sphinxRTT.updateRtt(replyTimePerHop)
        }
    }

    private fun getTimeoutEstimate(greedyRoute: Boolean): Long {
        return if (greedyRoute) {
            greedyRTT.rttTimeout()
        } else {
            sphinxRTT.rttTimeout()
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
                    DhtResponse::class.java -> processDhtResponse(payload as DhtResponse, false)
                    ClientDataMessage::class.java -> processClientDataMessage(payload as ClientDataMessage)
                    else -> log().error("Unknown message type ${payload.javaClass.name}")
                }
            } else {
                val forwardMessage = SphinxRoutedMessage(messageResult.forwardMessage!!.messageBytes)
                val wrapper = NeighbourSendSphinxMessage(messageResult.nextNode!!, forwardMessage)
                neighbourLinkActor.tell(wrapper, self)
            }
        } else {
            log().warn("Bad message received")
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
            log().warn("Node not ready for client key ${request.key}")
            sender.tell(ClientDhtResponse(request.key, false, request.data), self)
            return
        }
        val now = Clock.systemUTC().instant()
        val initialProbes = findNearest(request.key, ALPHA)
        if (initialProbes.isEmpty()) {
            log().warn("No nearest nodes for client key ${request.key}")
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
            log().warn("Node not ready for client data")
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
                val destinationAddress = findExact(message.destination)
                if (destinationAddress == null) {
                    log().warn("Node not known ${message.destination}")
                    sender.tell(ClientSendResult(message.destination, false), self)
                    return
                }
                clientCache.put(destinationAddress.identity.id, destinationAddress)
                sendGreedyMessage(destinationAddress, clientDataMessage)
            }
        } else {
            routeCache.put(message.destination, knownPath)
            sendSphinxMessage(knownPath, clientDataMessage)
        }
        sender.tell(ClientSendResult(message.destination, true), self)
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

}
