package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.*
import uk.co.nesbit.network.mocknet.CloseRequest
import uk.co.nesbit.network.mocknet.OpenRequest
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit

class NeighbourSendGreedyMessage(val networkAddress: NetworkAddressInfo, val payload: ByteArray)
class NeighbourSendSphinxMessage(val nextHop: SecureHash, val message: SphinxRoutedMessage)
class NeighbourReceivedGreedyMessage(val replyPath: List<VersionedIdentity>, val payload: ByteArray)
class NeighbourUpdate(val localId: NetworkAddressInfo, val addresses: List<NetworkAddressInfo>)

class NeighbourLinkActor(
    private val keyService: KeyService,
    private val networkConfig: NetworkConfiguration,
    private val physicalNetworkActor: ActorRef
) :
    UntypedBaseActorWithLoggingAndTimers() {
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
        const val LINK_CHECK_INTERVAL_MS = 5000L
        const val HEARTBEAT_INTERVAL_MS = 3L * LINK_CHECK_INTERVAL_MS
    }

    private class CheckStaticLinks(val first: Boolean)
    private class LinkState(val linkId: LinkId, val receiveSecureId: ByteArray, val created: Instant) {
        var identity: VersionedIdentity? = null
        var sendSecureId: ByteArray? = null
        var treeState: TreeState? = null
    }

    private class ParentInfo(
        var parent: LinkId? = null,
        var startPoint: Int = 0
    )

    private val networkId: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        keyService.generateNetworkID(networkConfig.networkId.toString())
    }

    private val owners = mutableSetOf<ActorRef>()
    private val clock = Clock.systemUTC()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val linkRequestPending = mutableSetOf<Address>()
    private val addresses = mutableMapOf<SecureHash, LinkId>()
    private val linkStates = mutableMapOf<LinkId, LinkState>()

    private var parents: List<ParentInfo> = listOf(ParentInfo(), ParentInfo(), ParentInfo())
    private var selfAddress: NetworkAddressInfo =
        NetworkAddressInfo(keyService.getVersion(networkId), listOf(networkId), listOf(networkId), listOf(networkId))
    private var changed: Boolean = true
    private var parentHeartbeat: Boolean = false
    private var neighbourChanged: Boolean = false
    private var lastTreeSent: Instant = Instant.ofEpochMilli(0L)
    private var lastNeighbourSent: Instant = Instant.ofEpochMilli(0L)

    override fun preStart() {
        super.preStart()
        //log().info("Starting NeighbourLinkActor")
        physicalNetworkActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
            "staticLinkStartup",
            CheckStaticLinks(true),
            keyService.random.nextInt(LINK_CHECK_INTERVAL_MS.toInt()).toLong().millis()
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
            is WatchRequest -> onWatchRequest()
            is CheckStaticLinks -> onCheckStaticLinks(message)
            is LinkInfo -> onLinkStatusChange(message)
            is LinkReceivedMessage -> onLinkReceivedMessage(message)
            is NeighbourSendGreedyMessage -> onSendGreedyMessage(message)
            is NeighbourSendSphinxMessage -> onSendSphinxMessage(message)
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

    private fun onCheckStaticLinks(check: CheckStaticLinks) {
        if (check.first) {
            timers.startTimerWithFixedDelay(
                "staticLinkPoller",
                CheckStaticLinks(false),
                LINK_CHECK_INTERVAL_MS.millis()
            )
        }
        openStaticLinks()
        val now = clock.instant()
        removeStaleInfo(now)
        calcParents()
        //log().info("status changed: $changed parentHeartbeat: $parentHeartbeat neighbourChanged: $neighbourChanged")
        if (neighbourChanged || changed) {
            sendNeighbourUpdate(now)
        }
        val heartbeat = ChronoUnit.MILLIS.between(lastTreeSent, now) >= HEARTBEAT_INTERVAL_MS
        if (heartbeat) {
            for (parent in parents) {
                if (parent.parent == null) {
                    parentHeartbeat = true
                }
            }
        }
        if (changed || parentHeartbeat) {
            sendTreeStatus(now)
        }
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
                    log().info("Stale state")
                    linkState.treeState = null
                    neighbourChanged = true
                }
            }
        }
    }

    private fun openStaticLinks() {
        if (linkRequestPending.size < MAX_CONNECTS) {
            for (expectedLink in networkConfig.staticRoutes.shuffled()) {
                if (!staticLinkStatus.containsKey(expectedLink)
                    && !linkRequestPending.contains(expectedLink)
                    && expectedLink != networkConfig.networkId // no self-links
                ) {
                    log().info("open static link to $expectedLink")
                    linkRequestPending += expectedLink
                    physicalNetworkActor.tell(OpenRequest(expectedLink), self)
                    if (linkRequestPending.size >= MAX_CONNECTS) break
                }
            }
        }
    }

    private fun sendNeighbourUpdate(now: Instant) {
        if (ChronoUnit.MILLIS.between(lastNeighbourSent, now) >= LINK_CHECK_INTERVAL_MS) {
            neighbourChanged = false
            lastNeighbourSent = now
            val neighbours = linkStates.values.mapNotNull { it.treeState?.treeAddress }
            log().info("Send neighbour update")
            val neighbourUpdate = NeighbourUpdate(selfAddress, neighbours)
            for (owner in owners) {
                owner.tell(neighbourUpdate, self)
            }
        }
    }

    private fun calcParent(index: Int) {
        val currentParent = parents[index]
        val allStates = linkStates.values.toList()
        val valid = allStates
            .filter { it.treeState != null }
            .filter { entry -> entry.treeState!!.shortPaths[index].none { it.id == networkId } }
        if (valid.isEmpty()) {
            currentParent.startPoint = 0
            currentParent.parent = null
            return
        }
        val neighbourRoots = valid.map { it.treeState!!.roots[index] }
        val minRoot = (neighbourRoots + networkId)
            .minBy { SecureHash.secureHash(concatByteArrays(index.toByteArray(), it.bytes)) }!!
        if (minRoot == networkId) {
            currentParent.startPoint = 0
            currentParent.parent = null
            return
        }
        val withBestRoot = valid.filter { it.treeState!!.roots[index] == minRoot }
        val minDepth = withBestRoot.map { it.treeState!!.depths[index] }.min()!!
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

    private fun calcParents() {
        calcParent(0)
        calcParent(1)
        calcParent(2)
        val oldSelfAddress = selfAddress
        calcSelfAddress()
        if (oldSelfAddress != selfAddress) {
            keyService.incrementAndGetVersion(networkId)
            calcSelfAddress()
            changed = true
        }
    }


    private fun sendMessageToLink(
        linkState: LinkState,
        message: Message
    ) {
        val oneHopMessage = OneHopMessage.createOneHopMessage(0, 0, message)
        val networkMessage = LinkSendMessage(linkState.linkId, oneHopMessage.serialize())
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
        if (ChronoUnit.MILLIS.between(lastTreeSent, now) >= LINK_CHECK_INTERVAL_MS) {
            changed = false
            parentHeartbeat = false
            lastTreeSent = now
            for (neighbour in linkStates.values) {
                sendTreeForLink(now, neighbour.linkId)
            }
            log().info("tree ${keyService.getVersion(networkId).currentVersion.version} ${selfAddress.paths.map { "${it.size}:${it.first()}" }}")
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        val linkId = linkInfo.linkId
        //log().info("onLinkStatusChange $linkId $linkInfo")
        linkRequestPending -= linkInfo.route.to
        if (linkInfo.status.active) {
            if (linkInfo.route.to in networkConfig.staticRoutes) {
                val prevLink = staticLinkStatus[linkInfo.route.to]
                if (prevLink != null) {
                    val from = linkInfo.route.to as NetworkAddress
                    val preferActive = (from.id >= networkConfig.networkId.id)
                    if (preferActive xor (linkInfo.status == LinkStatus.LINK_UP_PASSIVE)) {
                        log().warning("close duplicate link $linkId")
                        physicalNetworkActor.tell(CloseRequest(linkId), self)
                        return
                    } else {
                        log().warning("close duplicate link $prevLink")
                        physicalNetworkActor.tell(CloseRequest(prevLink), self)
                    }
                }
                staticLinkStatus[linkInfo.route.to] = linkId
            }
            sendHello(linkId)
        } else {
            log().info("Link lost $linkInfo")
            staticLinkStatus.remove(linkInfo.route.to, linkId)
            val oldState = linkStates.remove(linkId)
            if (oldState?.identity != null) {
                addresses.remove(oldState.identity!!.id)
            }
            calcParents()
            val now = clock.instant()
            sendNeighbourUpdate(now)
            if (changed) {
                sendTreeStatus(now)
            }
        }
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
        val oneHopMessage = try {
            OneHopMessage.deserialize(message.msg)
        } catch (ex: Exception) {
            log().error("Bad OneHopMessage ${ex.message}")
            physicalNetworkActor.tell(CloseRequest(message.linkId), self)
            return
        }
        val payloadMessage = oneHopMessage.payloadMessage
        when (payloadMessage) {
            is Hello -> processHelloMessage(message.linkId, payloadMessage)
            is TreeState -> processTreeStateMessage(message.linkId, payloadMessage)
            is GreedyRoutedMessage -> processGreedyRoutedMessage(message.linkId, payloadMessage)
            is SphinxRoutedMessage -> {
                for (owner in owners) {
                    owner.tell(payloadMessage, self)
                }
            }
            is AckMessage -> {
                //
            }
            else -> log().error("Unknown message type $message")
        }
    }

    private fun processHelloMessage(sourceLink: LinkId, hello: Hello) {
        val linkState = linkStates[sourceLink]
        if (linkState == null) {
            log().warning("LinkId not known $sourceLink")
            return
        }
        try {
            hello.verify()
        } catch (ex: Exception) {
            log().error("Bad Hello message")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        //log().info("process hello message from $sourceLink")
        val prevAddress = addresses[hello.sourceId.id]
        if (prevAddress != null && prevAddress != sourceLink) {
            log().info("close link from duplicate address")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        linkState.identity = hello.sourceId
        linkState.sendSecureId = hello.secureLinkId
        addresses[hello.sourceId.id] = sourceLink
        calcParents()
        val now = clock.instant()
        sendNeighbourUpdate(now)
        sendTreeForLink(now, sourceLink)
    }

    private fun processTreeStateMessage(sourceLink: LinkId, tree: TreeState) {
        //log().info("process tree message")
        val now = clock.instant()
        //log().info("tree delay ${ChronoUnit.MILLIS.between(tree.path.path.last().timestamp,now)}")
        val linkState = linkStates[sourceLink]
        if (linkState?.identity == null) {
            log().error("No hello yet received on $sourceLink")
            return
        }
        val oldState = linkState.treeState
        linkState.treeState = null
        if (tree.stale(now)) {
            log().warning("Discard Stale Tree State")
            return
        }
        try {
            tree.verify(linkState.receiveSecureId, keyService.getVersion(networkId), now)
        } catch (ex: Exception) {
            log().error("Bad Tree message ${ex.message}")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        val neighbour = tree.treeAddress
        if (linkState.identity!!.id != neighbour.identity.id) {
            log().error("Neighbour on $sourceLink doesn't match")
            return
        }
        if (linkState.identity!!.currentVersion.version > neighbour.identity.currentVersion.version) {
            log().error("Neighbour on $sourceLink has stale version")
            return
        }
        linkState.identity = neighbour.identity
        linkState.treeState = tree
        calcParents()
        if (tree.treeAddress != oldState?.treeAddress) {
            neighbourChanged = true
        }
        if (neighbourChanged || changed) {
            sendNeighbourUpdate(now)
        }
        val parentDists =
            listOf(selfAddress.treeAddress1.size, selfAddress.treeAddress2.size, selfAddress.treeAddress3.size)
        val nearestParent = parentDists.withIndex().minBy { it.value }!!.index
        if (sourceLink == parents[nearestParent].parent) {
            parentHeartbeat = true
        }
        //log().info("status changed: $changed parentHeartbeat: $parentHeartbeat neighbourChanged: $neighbourChanged")
        if (changed || parentHeartbeat) {
            sendTreeStatus(now)
        }
    }

    private fun findGreedyNextHop(
        treeAddress: NetworkAddressInfo,
        sourceLink: LinkId
    ): LinkState? {
        val neighbour = addresses[treeAddress.identity.id]
        if (neighbour != null) {
            return linkStates[neighbour]
        }
        if (treeAddress.roots != selfAddress.roots) {
            log().warning("Unmatched root dropping")
            return null
        }
        var best: LinkState? = null
        var bestDistance = selfAddress.greedyDist(treeAddress)
        for (neighbourState in linkStates.values) {
            if (neighbourState.linkId != sourceLink
                && neighbourState.identity != null
                && neighbourState.sendSecureId != null
                && neighbourState.treeState != null
                && neighbourState.treeState!!.roots == selfAddress.roots
            ) {
                val hopCount = neighbourState.treeState!!.treeAddress.greedyDist(treeAddress)
                if (hopCount < bestDistance) {
                    bestDistance = hopCount
                    best = neighbourState
                }
            }
        }
        return best
    }

    private fun processGreedyRoutedMessage(sourceLink: LinkId, payloadMessage: GreedyRoutedMessage) {
        val now = clock.instant()
        val linkState = linkStates[sourceLink]
        if (linkState?.identity == null) {
            log().warning("No hello yet received on $sourceLink for greedy message")
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
            log().warning("Bad GreedyRoutedMessage ${ex.message}")
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
                //log().warning("No forward route found dropping message to ${payloadMessage.treeAddress} from $selfAddress")
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

    private fun onSendGreedyMessage(messageRequest: NeighbourSendGreedyMessage) {
        val nextHop = findGreedyNextHop(messageRequest.networkAddress, SimpleLinkId(-1))
        if (nextHop == null) {
            log().warning("Unable to route to ${messageRequest.networkAddress}")
            return
        }
        val hopCountMax = selfAddress.greedyDist(messageRequest.networkAddress)
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
            log().warning("Unable to route to neighbour ${messageRequest.nextHop}")
            return
        }
        val nextHop = linkStates[nextHopLink]
        if (nextHop == null) {
            log().warning("Unable to route to neighbour ${messageRequest.nextHop}")
            return
        }
        sendMessageToLink(nextHop, messageRequest.message)
    }
}