package uk.co.nesbit.network.treeEngine

import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.crypto.trace
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.*
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.simpleactor.*
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.random.Random

class NeighbourSendGreedyMessage(val networkAddress: NetworkAddressInfo, val payload: ByteArray)
class NeighbourSendSphinxMessage(val nextHop: SecureHash, val message: SphinxRoutedMessage)
class NeighbourReceivedGreedyMessage(val replyPath: List<VersionedIdentity>, val payload: ByteArray)
class NeighbourUpdate(val localId: NetworkAddressInfo, val addresses: List<NetworkAddressInfo>)

class NeighbourLinkActor(
    private val keyService: KeyService,
    private val networkConfig: NetworkConfiguration,
    private val physicalNetworkActor: ActorRef
) :
    AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            networkConfig: NetworkConfiguration,
            physicalNetworkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, networkConfig, physicalNetworkActor)
        }

        const val MAX_CONNECTS = 5
        const val HELLO_TIMEOUT_MS = 120000L
        const val JITTER_MS = 1000
        const val HEARTBEAT_INTERVAL_MS = 5000L
        const val DEAD_LINK_MS = 120000L
        const val FREEZE_TIME = 10000L
        const val LATENCY_HIGH = 500L
        const val LATENCY_LOW = 25L
    }

    private class CheckStaticLinks
    private class LinkState(val linkId: LinkId, val receiveSecureId: ByteArray, val created: Instant) {
        var identity: VersionedIdentity? = null
        var sendSecureId: ByteArray? = null
        var treeState: TreeState? = null
        var verified: Boolean = false
        var lastMessage: Instant = created
    }

    private class ParentInfo(
        var parent: LinkId? = null,
        var startPoint: Int = 0
    )

    private val networkId: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val key = keyService.generateNetworkID(networkConfig.networkId.toString())
        log().info("new network id $key for address ${networkConfig.networkId}")
        key
    }

    private val owners = mutableSetOf<ActorRef>()
    private val clock = Clock.systemUTC()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val staticLinkReverseStatus = mutableMapOf<LinkId, Address>()
    private val staticLinkAlternate = mutableMapOf<Address, LinkId>()
    private val staticLinkReverseAlternate = mutableMapOf<LinkId, Address>()
    private val linkRequestPending = mutableSetOf<Address>()
    private val addresses = mutableMapOf<SecureHash, LinkId>()
    private val linkStates = mutableMapOf<LinkId, LinkState>()
    private val rootExpiryCache = mutableMapOf<SecureHash, Pair<Int, Instant>>()

    private var parents: List<ParentInfo> = listOf(ParentInfo(), ParentInfo(), ParentInfo())
    private var selfAddress: NetworkAddressInfo =
        NetworkAddressInfo(keyService.getVersion(networkId), listOf(networkId), listOf(networkId), listOf(networkId))
    private var neighbourChanged: Boolean = true
    private var treeChanged: Boolean = true
    private val localRand = Random(keyService.random.nextLong())
    private var heartbeatRate = HEARTBEAT_INTERVAL_MS
    private var pChangeTime = clock.instant()

    override fun preStart() {
        super.preStart()
        //log().info("Starting NeighbourLinkActor")
        physicalNetworkActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
            "staticLinkStartup",
            CheckStaticLinks(),
            localRand.nextInt(HEARTBEAT_INTERVAL_MS.toInt()).toLong().millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped NeighbourLinkActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().warn("Restart NeighbourLinkActor")
        physicalNetworkActor.tell(CloseAllRequest(), self)
    }

    override fun onReceive(message: Any) {
        when (message) {
            is WatchRequest -> onWatchRequest()
            is Terminated -> onDeath(message)
            is CheckStaticLinks -> onCheckStaticLinks()
            is LinkInfo -> onLinkStatusChange(message)
            is LinkReceivedMessage -> onLinkReceivedMessage(message)
            is NeighbourSendGreedyMessage -> onSendGreedyMessage(message)
            is NeighbourSendSphinxMessage -> onSendSphinxMessage(message)
            else -> throw IllegalArgumentException("Unknown message type ${message.javaClass.name}")
        }
    }

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
        neighbourChanged = true
    }

    private fun onDeath(message: Terminated) {
        owners -= message.actor
    }

    private fun onCheckStaticLinks() {
        timers.startSingleTimer(
            "staticLinkPoller",
            CheckStaticLinks(),
            (heartbeatRate + localRand.nextInt(JITTER_MS) - (JITTER_MS / 2)).millis()
        )
        openStaticLinks()
        val now = clock.instant()
        removeStaleInfo(now)
        calcParents(now)
        //log().info("status changed: $changed parentHeartbeat: $parentHeartbeat neighbourChanged: $neighbourChanged")
        sendNeighbourUpdate()
        sendTreeStatus(now)
    }

    private fun removeStaleInfo(now: Instant) {
        val linkStateIterator = linkStates.iterator()
        while (linkStateIterator.hasNext()) {
            val linkState = linkStateIterator.next().value
            if (linkState.identity == null
                && ChronoUnit.MILLIS.between(linkState.created, now) > HELLO_TIMEOUT_MS
            ) {
                log().error("Hello timed out ${linkState.linkId}")
                physicalNetworkActor.tell(CloseRequest(linkState.linkId), self)
                linkStateIterator.remove()
                neighbourChanged = true
            } else {
                val treeState = linkState.treeState
                if (treeState != null && treeState.stale(now)) {
                    log().info("Stale state ${linkState.linkId}")
                    linkState.treeState = null
                    linkState.verified = false
                    neighbourChanged = true
                } else if (treeState == null
                    && ChronoUnit.MILLIS.between(linkState.lastMessage, now) >= DEAD_LINK_MS
                ) {
                    log().error("Link silent closing ${linkState.linkId}")
                    physicalNetworkActor.tell(CloseRequest(linkState.linkId), self)
                    linkStateIterator.remove()
                    neighbourChanged = true
                }
            }
        }
    }

    private fun openStaticLinks() {
        if (linkRequestPending.size < MAX_CONNECTS) {
            for (expectedLink in networkConfig.staticRoutes.shuffled()) {
                if (!staticLinkStatus.containsKey(expectedLink)
                    && !staticLinkAlternate.containsKey(expectedLink)
                    && !linkRequestPending.contains(expectedLink)
                    && expectedLink != networkConfig.networkId // no self-links
                ) {
                    log().info(
                        "open static link to $expectedLink " +
                                "expected ${networkConfig.staticRoutes.size} " +
                                "open ${staticLinkStatus.size} " +
                                "pending ${linkRequestPending.size} " +
                                "aliased ${staticLinkAlternate.size} " +
                                "remaining ${networkConfig.staticRoutes.size - staticLinkStatus.size - staticLinkAlternate.size}"
                    )
                    linkRequestPending += expectedLink
                    physicalNetworkActor.tell(OpenRequest(expectedLink), self)
                    if (linkRequestPending.size >= MAX_CONNECTS) break
                }
            }
        }
    }

    private fun sendNeighbourUpdate() {
        if (neighbourChanged) {
            neighbourChanged = false
            val neighbours = linkStates.values.mapNotNull { it.treeState?.treeAddress }
            log().info("Send neighbour update")
            val neighbourUpdate = NeighbourUpdate(selfAddress, neighbours)
            for (owner in owners) {
                owner.tell(neighbourUpdate, self)
            }
        }
    }

    private fun calcParent(index: Int, now: Instant) {
        val currentParent = parents[index]
        val allStates = linkStates.values.toList()
        val valid = allStates
            .filter { it.treeState != null }
            .filter { entry -> entry.treeState!!.shortPaths[index].none { it.id == networkId } }
            .filter { entry2 ->
                val root = entry2.treeState!!.paths[index].path.first()
                val cached = rootExpiryCache[root.identity.id]!!
                if (cached.first + entry2.treeState!!.depths[index] - 1 > keyService.maxVersion) {
                    // we can't expect stale roots to propagate so further out we are more version headroom needed
                    return@filter false
                }
                val age = cached.second
                ChronoUnit.MILLIS.between(age, now) < 2L * entry2.treeState!!.depths[index] * heartbeatRate
            }
        if (valid.isEmpty()) {
            currentParent.startPoint = 0
            currentParent.parent = null
            return
        }
        val neighbourRoots = valid.map { it.treeState!!.roots[index] }
        val minRoot = (neighbourRoots + networkId)
            .minByOrNull { SecureHash.secureHash(concatByteArrays(index.toByteArray(), it.bytes)) }!!
        if (minRoot == networkId) {
            currentParent.startPoint = 0
            currentParent.parent = null
            return
        }
        val withBestRoot = valid.filter { it.treeState!!.roots[index] == minRoot }
        val minDepth = withBestRoot.minOf { it.treeState!!.depths[index] }
        currentParent.startPoint = currentParent.startPoint.rem(allStates.size)
        var parentSeen = false
        for (i in allStates.indices) {
            val j = (i + currentParent.startPoint).rem(allStates.size)
            val curr = allStates[j]
            if (currentParent.parent == curr.linkId) {
                parentSeen = true
            }
            if (allStates[j] in withBestRoot) {
                val currentDepth = curr.treeState!!.depths[index]
                if (currentDepth == minDepth) {
                    currentParent.parent = curr.linkId
                    if (parentSeen) {
                        currentParent.startPoint = j
                    }
                    break
                }
            }
        }
    }

    private fun parentPath(index: Int): SecurePath? {
        val parent = parents[index].parent
        val parentTree = if (parent == null) null else linkStates[parent]?.treeState
        return if (parentTree == null) {
            null
        } else {
            parentTree.paths[index]
        }
    }

    private fun treePath(index: Int): List<SecureHash> {
        val parent = parents[index].parent
        val parentTree = if (parent == null) null else linkStates[parent]?.treeState
        return if (parentTree == null) {
            listOf(networkId)
        } else {
            parentTree.treeAddress.paths[index] + networkId
        }
    }

    private fun calcSelfAddress() {
        val parentPath1 = treePath(0)
        val parentPath2 = treePath(1)
        val parentPath3 = treePath(2)
        selfAddress = NetworkAddressInfo(keyService.getVersion(networkId), parentPath1, parentPath2, parentPath3)
    }

    private fun calcParents(now: Instant) {
        val rootTicks = mutableSetOf<SecureHash>()
        for (linkState in linkStates.values) {
            val tree = linkState.treeState
            if (tree != null && !linkState.verified) {
                try {
                    // The verify operation is one of the most CPU intensive parts of the code
                    // we try to minimize unnecessary calcs, whilst ensuring freshness
                    tree.verify(linkState.receiveSecureId, keyService.getVersion(networkId), now)
                    linkState.verified = true
                    for (path in tree.paths) {
                        val root = path.path.first()
                        val prevTimes = rootExpiryCache[root.identity.id]
                        if (prevTimes == null || prevTimes.first < root.identity.currentVersion.version) {
                            rootExpiryCache[root.identity.id] = Pair(root.identity.currentVersion.version, now)
                            rootTicks += root.identity.id
                        }
                    }
                } catch (ex: Exception) {
                    log().error("Bad Tree message ${ex.message}")
                    linkState.treeState = null
                    linkState.verified = false
                    physicalNetworkActor.tell(CloseRequest(linkState.linkId), self)
                }
            }
        }
        calcParent(0, now)
        calcParent(1, now)
        calcParent(2, now)
        val oldSelfAddress = selfAddress
        calcSelfAddress()
        if (parents.count { it.parent == null } == 1) { // rotate stable root keys
            incrementVersion()
        } else if (oldSelfAddress.treeAddress1 != selfAddress.treeAddress1
            || oldSelfAddress.treeAddress2 != selfAddress.treeAddress2
            || oldSelfAddress.treeAddress3 != selfAddress.treeAddress3
            || oldSelfAddress.identity.identity != selfAddress.identity.identity
        ) {
            incrementVersion()
        }
        if (selfAddress.paths.any { it.first() in rootTicks }) {
            treeChanged = true
        }
    }

    private fun incrementVersion() {
        keyService.incrementAndGetVersion(networkId)
        val version = keyService.getVersion(networkId)
        log().info("Version incremented to ${version.currentVersion.version}")
        if (version.currentVersion.version >= keyService.maxVersion) {
            log().warn("NetworkId Key exhausted rotating identity")
            self.tell(Kill, self)
            return
        }
        calcSelfAddress()
        neighbourChanged = true
        treeChanged = true
    }

    private fun sendMessageToLink(
        linkState: LinkState,
        message: Message
    ) {
        val oneHopMessage = OneHopMessage.createOneHopMessage(message)
        val networkMessage =
            LinkSendMessage(linkState.linkId, oneHopMessage.serialize())
        physicalNetworkActor.tell(networkMessage, self)
    }

    private fun sendTreeForLink(now: Instant, linkId: LinkId) {
        val linkState = linkStates[linkId]
        if (linkState?.identity == null) {
            //log().info("handshake not complete $linkId")
            return
        }
        val parentPath1 = parentPath(0)
        val parentPath2 = parentPath(1)
        val parentPath3 = parentPath(2)
        val treeState = TreeState.createTreeState(
            parentPath1,
            parentPath2,
            parentPath3,
            linkState.sendSecureId!!,
            keyService.getVersion(networkId),
            linkState.identity!!,
            keyService,
            now
        )
        //log().info("send ${linkState.linkId} ${linkState.seqNum} ${linkState.ackSeqNum}")
        sendMessageToLink(linkState, treeState)
    }

    private fun sendTreeStatus(now: Instant) {
        if (treeChanged) {
            treeChanged = false
            for (neighbour in linkStates.values) {
                sendTreeForLink(now, neighbour.linkId)
            }
            log().trace { "tree ${keyService.getVersion(networkId).currentVersion.version} ${selfAddress.paths.map { "${it.size}:${it.first()}" }}" }
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        val linkId = linkInfo.linkId
        log().info("onLinkStatusChange $linkId $linkInfo")
        if (linkInfo.status.active) {
            if (linkInfo.status == LinkStatus.LINK_UP_ACTIVE
                && linkInfo.route.to in networkConfig.staticRoutes
            ) {
                linkRequestPending -= linkInfo.route.to
                val prevLink = staticLinkStatus[linkInfo.route.to]
                if (prevLink != null) {
                    log().warn("close previous static link $prevLink")
                    physicalNetworkActor.tell(CloseRequest(prevLink), self)
                }
                staticLinkStatus[linkInfo.route.to] = linkId
                staticLinkReverseStatus[linkId] = linkInfo.route.to
            }
            sendHello(linkId)
        } else {
            log().info("Link lost $linkId $linkInfo")
            linkRequestPending -= linkInfo.route.to
            staticLinkStatus.remove(linkInfo.route.to, linkId)
            staticLinkReverseStatus.remove(linkId)
            val equivalentAddress = staticLinkReverseAlternate.remove(linkId)
            if (equivalentAddress != null) {
                staticLinkAlternate.remove(equivalentAddress)
            }
            val oldState = linkStates.remove(linkId)
            if (oldState?.identity != null) {
                if (addresses.remove(oldState.identity!!.id, linkId)) {
                    for (altLinkState in linkStates.values) {
                        if (altLinkState.identity?.id == oldState.identity!!.id) {
                            addresses[altLinkState.identity!!.id] = altLinkState.linkId
                            break
                        }
                    }
                }
            }
            neighbourChanged = true
        }
        openStaticLinks()
    }

    private fun sendHello(linkId: LinkId) {
        //log().info("Send hello message to $linkId")
        val helloMessage = Hello.createHello(networkId, keyService)
        val linkState = LinkState(linkId, helloMessage.secureLinkId, clock.instant())
        linkStates[linkId] = linkState
        sendMessageToLink(linkState, helloMessage)
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        //log().info("onLinkReceivedMessage $message")
        val linksState = linkStates[message.linkId]
        if (linksState == null) {
            log().error("Message on unknown channel ${message.linkId}")
            physicalNetworkActor.tell(CloseRequest(message.linkId), self)
            return
        }
        cpuLoadCheck(message)
        val oneHopMessage = try {
            OneHopMessage.deserialize(message.msg)
        } catch (ex: Exception) {
            log().error("Bad OneHopMessage ${ex.message}")
            physicalNetworkActor.tell(CloseRequest(message.linkId), self)
            return
        }
        linksState.lastMessage = Clock.systemUTC().instant()
        when (val payloadMessage = oneHopMessage.payloadMessage) {
            is Hello -> processHelloMessage(message.linkId, payloadMessage)
            is TreeState -> processTreeStateMessage(message.linkId, payloadMessage)
            is GreedyRoutedMessage -> processGreedyRoutedMessage(message.linkId, payloadMessage)
            is SphinxRoutedMessage -> processSphinxRoutedMessage(payloadMessage)
            else -> log().error("Unknown message type ${message.javaClass.name}")
        }
    }

    private fun cpuLoadCheck(message: LinkReceivedMessage) {
        val now = clock.instant()
        if (ChronoUnit.MILLIS.between(pChangeTime, now) > FREEZE_TIME) {
            val localQueueLatency = ChronoUnit.MILLIS.between(message.received, now)
            val oldRate = heartbeatRate
            if (localQueueLatency > LATENCY_HIGH) {
                heartbeatRate =
                    (2L * heartbeatRate).coerceIn(HEARTBEAT_INTERVAL_MS, TreeState.TimeErrorPerHop / 2L)
                pChangeTime = now
                if (oldRate != heartbeatRate) {
                    log().warn("heartbeat frequency down queue delay: $localQueueLatency timer interval: $heartbeatRate")
                }
            } else if (localQueueLatency < LATENCY_LOW) {
                heartbeatRate = (heartbeatRate - 200L).coerceIn(HEARTBEAT_INTERVAL_MS, TreeState.TimeErrorPerHop / 2L)
                pChangeTime = now
                if (oldRate != heartbeatRate) {
                    log().warn("heartbeat frequency up queue delay: $localQueueLatency timer interval: $heartbeatRate")
                }
            }
        }
    }

    private fun processHelloMessage(sourceLink: LinkId, hello: Hello) {
        val linkState = linkStates[sourceLink]
        if (linkState == null) {
            log().warn("LinkId not known $sourceLink")
            return
        }
        try {
            hello.verify(keyService)
        } catch (ex: Exception) {
            log().error("Bad Hello message")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        if (networkConfig.denyListedSources.any { it.toString() == hello.sourceId.identity.publicAddress }) {
            log().error("deny listed peer id")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        if (!networkConfig.allowDynamicRouting && networkConfig.staticRoutes.none { it.toString() == hello.sourceId.identity.publicAddress }) {
            log().error("no dynamic links from non-static peers allowed")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        //log().info("process hello message from $sourceLink")
        val prevAddress = addresses[hello.sourceId.id]
        if (prevAddress != null && prevAddress != sourceLink) {
            val prevLink = linkStates[prevAddress]
            if (prevLink != null && networkId < hello.sourceId.id) {
                val staticTarget = staticLinkReverseStatus[sourceLink]
                if (staticTarget != null) {
                    log().info("map preferred remote link equivalent $staticTarget via ${prevLink.linkId}")
                    staticLinkAlternate[staticTarget] = prevLink.linkId
                    staticLinkReverseAlternate[prevLink.linkId] = staticTarget
                    log().info("close link $sourceLink from duplicate address")
                    physicalNetworkActor.tell(CloseRequest(sourceLink), self)
                    return
                }
            }
        }
        linkState.identity = hello.sourceId
        linkState.sendSecureId = hello.secureLinkId
        addresses[hello.sourceId.id] = sourceLink
        neighbourChanged = true
        treeChanged = true
    }

    private fun processTreeStateMessage(sourceLink: LinkId, tree: TreeState) {
        //log().info("process tree message")
        val now = clock.instant()
        //log().info("tree delay ${ChronoUnit.MILLIS.between(tree.path.path.last().timestamp,now)}")
        val linkState = linkStates[sourceLink]
        if (linkState?.identity == null) {
            log().warn("No hello yet received on $sourceLink")
            return
        }
        val neighbour = tree.treeAddress
        if (linkState.identity!!.id != neighbour.identity.id) {
            log().error("Neighbour on $sourceLink doesn't match")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        if (linkState.identity!!.currentVersion.version > neighbour.identity.currentVersion.version) {
            log().error("Neighbour on $sourceLink has stale version")
            return
        }
        val oldState = linkState.treeState
        if (oldState == tree) {
            return
        }
        linkState.treeState = null
        linkState.verified = false
        if (tree.stale(now)) {
            log().warn("Discard Stale Tree State")
            return
        }
        linkState.identity = neighbour.identity
        linkState.treeState = tree
        if (tree.treeAddress != oldState?.treeAddress) {
            neighbourChanged = true
        }
    }

    private fun findGreedyNextHop(
        treeAddress: NetworkAddressInfo,
        sourceLink: LinkId
    ): LinkState? {
        val neighbour = addresses[treeAddress.identity.id]
        if (neighbour != null) {
            val linkState = linkStates[neighbour]
            if (linkState?.identity != null
                && linkState.sendSecureId != null
            ) {
                return linkState
            }
        }
        val selfDistance = selfAddress.greedyDist(treeAddress)
        val eligible = mutableListOf<LinkState>()
        for (neighbourState in linkStates.values) {
            if (neighbourState.linkId != sourceLink
                && neighbourState.identity != null
                && neighbourState.sendSecureId != null
                && neighbourState.treeState != null
            ) {
                val hopCount = neighbourState.treeState!!.treeAddress.greedyDist(treeAddress)
                if (hopCount < selfDistance) {
                    eligible += neighbourState
                }
            }
        }
        if (eligible.isEmpty()) {
            return null
        }
        return eligible[localRand.nextInt(eligible.size)]
    }

    private fun processGreedyRoutedMessage(sourceLink: LinkId, payloadMessage: GreedyRoutedMessage) {
        val now = clock.instant()
        val linkState = linkStates[sourceLink]
        if (linkState?.identity == null) {
            log().warn("No hello yet received on $sourceLink for greedy message")
            return
        }
        val reversePath = try {
            payloadMessage.verify(
                networkId,
                linkState.receiveSecureId,
                linkState.identity!!,
                keyService,
                now
            )
        } catch (ex: Exception) {
            log().warn("Bad GreedyRoutedMessage ${ex.message}")
            return
        }
        if (reversePath.isNotEmpty()) {
            //log().info("packet arrived at destination")
            val messageReceived = NeighbourReceivedGreedyMessage(reversePath, payloadMessage.payload)
            for (owner in owners) {
                owner.tell(messageReceived, self)
            }
        } else {
            if (payloadMessage.ttl <= payloadMessage.pathInfo.size) {
                log().info("Expire message beyond ttl")
                return
            }
            val nextHop: LinkState? = findGreedyNextHop(payloadMessage.destination, sourceLink)
            if (nextHop == null) {
                log().warn("Unable to route forward to ${payloadMessage.destination} no improvement available")
                return
            }
            val forwardMessage = GreedyRoutedMessage.forwardGreedRoutedMessage(
                payloadMessage,
                nextHop.sendSecureId!!,
                keyService.getVersion(networkId),
                nextHop.identity!!,
                keyService,
                now
            )
            sendMessageToLink(nextHop, forwardMessage)
        }
    }

    private fun processSphinxRoutedMessage(payloadMessage: Message) {
        for (owner in owners) {
            owner.tell(payloadMessage, self)
        }
    }

    private fun onSendGreedyMessage(messageRequest: NeighbourSendGreedyMessage) {
        val nextHop = findGreedyNextHop(messageRequest.networkAddress, SimpleLinkId(-1))
        if (nextHop == null) {
            log().warn("Unable to route to ${messageRequest.networkAddress} no improvement available")
            return
        }
        var estimatedHops = selfAddress.greedyDist(messageRequest.networkAddress)
        if (estimatedHops == Int.MAX_VALUE) {
            val nextHopDist = nextHop.treeState?.treeAddress?.greedyDist(messageRequest.networkAddress)
            if (nextHopDist == null || nextHopDist == Int.MAX_VALUE) {
                log().warn("Unable to route to ${messageRequest.networkAddress} no shared roots")
                return
            }
            estimatedHops = nextHopDist + 1
        }
        val hopCountMax = (3 * estimatedHops) / 2
        val greedyRoutedMessage = GreedyRoutedMessage.createGreedRoutedMessage(
            messageRequest.networkAddress,
            hopCountMax,
            messageRequest.payload,
            nextHop.sendSecureId!!,
            keyService.getVersion(networkId),
            nextHop.identity!!,
            keyService,
            clock.instant()
        )
        sendMessageToLink(nextHop, greedyRoutedMessage)
    }

    private fun onSendSphinxMessage(messageRequest: NeighbourSendSphinxMessage) {
        val nextHopLink = addresses[messageRequest.nextHop]
        if (nextHopLink == null) {
            log().warn("Unable to route to neighbour ${messageRequest.nextHop} sphinx address no known")
            return
        }
        val nextHop = linkStates[nextHopLink]
        if (nextHop == null) {
            log().warn("Unable to route to neighbour ${messageRequest.nextHop} link not available")
            return
        }
        sendMessageToLink(nextHop, messageRequest.message)
    }
}