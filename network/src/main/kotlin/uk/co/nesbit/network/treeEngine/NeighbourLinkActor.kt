package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.*
import uk.co.nesbit.network.mocknet.CloseRequest
import uk.co.nesbit.network.mocknet.OpenRequest
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.lang.Integer.max
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
    AbstractActorWithLoggingAndTimers() {
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

        const val LINK_CHECK_INTERVAL_MS = 5000L
        const val HEARTBEAT_INTERVAL_MS = 3L * LINK_CHECK_INTERVAL_MS
        const val MIN_WINDOW_SIZE = 5
    }

    private class CheckStaticLinks(val first: Boolean)
    private class LinkState(
        val linkId: LinkId,
        val receiveSecureId: ByteArray,
        var seqNum: Int = 0,
        var ackSeqNum: Int = -1,
        var confirmedSeqNum: Int = 0,
        var ackSent: Int = -1,
        var linkCapacity: Int = MIN_WINDOW_SIZE,
        var identity: VersionedIdentity? = null,
        var sendSecureId: ByteArray? = null,
        var treeState: TreeState? = null
    )

    private val networkId: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        keyService.generateNetworkID(networkConfig.networkId.toString())
    }

    private val owners = mutableSetOf<ActorRef>()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val linkRequestPending = mutableSetOf<Address>()
    private val addresses = mutableMapOf<SecureHash, LinkId>()
    private val linkStates = mutableMapOf<LinkId, LinkState>()

    private var parent: LinkId? = null
    private var selfAddress: List<SecureHash> = listOf(networkId)
    private var startPoint: Int = 0
    private var lastDepth: Int = 0
    private var changed: Boolean = true
    private var lastSent: Instant = Instant.ofEpochMilli(0L)

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

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(CheckStaticLinks::class.java, ::onCheckStaticLinks)
            .match(LinkInfo::class.java, ::onLinkStatusChange)
            .match(LinkReceivedMessage::class.java, ::onLinkReceivedMessage)
            .match(NeighbourSendGreedyMessage::class.java, ::onSendGreedyMessage)
            .match(NeighbourSendSphinxMessage::class.java, ::onSendSphinxMessage)
            .build()

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onCheckStaticLinks(check: CheckStaticLinks) {
        if (check.first) {
            //log().info("Parent changed to self root $networkId ${keyService.getVersion(networkId).identity.publicAddress}")
            timers.startTimerWithFixedDelay(
                "staticLinkPoller",
                CheckStaticLinks(false),
                LINK_CHECK_INTERVAL_MS.millis()
            )
        }
        if (linkRequestPending.isEmpty()) {
            for (expectedLink in networkConfig.staticRoutes) {
                if (!staticLinkStatus.containsKey(expectedLink)) {
                    log().info("open static link to $expectedLink")
                    linkRequestPending += expectedLink
                    physicalNetworkActor.tell(OpenRequest(expectedLink), self)
                }
            }
        }
        for (linkState in linkStates.values) {
            if (linkState.ackSeqNum - linkState.ackSent > 0) {
                sendMessageToLink(linkState, AckMessage())
                --linkState.seqNum
            }
        }
        calcParent()
        val now = Clock.systemUTC().instant()
        val parentTree = if (parent == null) null else linkStates[parent!!]?.treeState
        val heartbeat = ChronoUnit.MILLIS.between(lastSent, now) >= HEARTBEAT_INTERVAL_MS
        val expired = ChronoUnit.MILLIS.between(lastSent, now) >= TreeState.TimeErrorPerHop
        if (parentTree == null && heartbeat) {
            changed = true
        } else if (expired) {
            for (linkState in linkStates.values) {
                val treeState = linkState.treeState
                if (treeState != null && treeState.stale(now)) {
                    log().info("Stale state")
                    linkState.treeState = null
                }
            }
            calcParent()
        }
        if (changed) {
            sendTreeStatus(now)
        }
    }

    private fun sendNeighbourUpdate() {
        val localAddress = NetworkAddressInfo(
            keyService.getVersion(networkId),
            selfAddress
        )
        val neighbours = linkStates.values.mapNotNull { it.treeState }.map {
            NetworkAddressInfo(
                it.path.path.last().identity,
                it.shortPath.map { it.id })
        }
        val neighbourUpdate = NeighbourUpdate(localAddress, neighbours)
        for (owner in owners) {
            owner.tell(neighbourUpdate, self)
        }
    }

    private fun calcParent() {
        val valid = linkStates.values
            .filter { it.treeState != null }
            .filter { entry -> entry.treeState!!.shortPath.none { it.id == networkId } }
        if (valid.isEmpty()) {
            if (parent != null) {
                log().info("reset A")
                parent = null
                selfAddress = listOf(networkId)
                changed = true
                lastDepth = 0
            }
            startPoint = 0
            return
        }
        val minRoot = valid.map { it.treeState!!.root }.min()!!
        if (minRoot > networkId) {
            if (parent != null) {
                log().info("reset B")
                parent = null
                selfAddress = listOf(networkId)
                changed = true
                lastDepth = 0
            }
            return
        }
        val withBestRoot = valid.filter { it.treeState!!.root == minRoot }
        val minDepth = withBestRoot.map { it.treeState!!.depth }.min()!!
        if (lastDepth != minDepth) {
            changed = true
            lastDepth = minDepth
        }
        startPoint = startPoint.rem(withBestRoot.size)
        var parentSeen = false
        for (i in withBestRoot.indices) {
            val j = (i + startPoint).rem(withBestRoot.size)
            if (parent != withBestRoot[j].linkId) {
                parentSeen = true
            }
            val currentDepth = withBestRoot[j].treeState!!.depth
            if (currentDepth == minDepth) {
                if (parent != withBestRoot[j].linkId) {
                    changed = true
                }
                parent = withBestRoot[j].linkId
                selfAddress = withBestRoot[j].treeState!!.shortPath.map { it.id } + networkId
                if (parentSeen) {
                    startPoint = j
                }
                break
            }
        }
    }

    private fun sendMessageToLink(
        linkState: LinkState,
        message: Message
    ) {
        val oneHopMessage = OneHopMessage.createOneHopMessage(linkState.seqNum++, linkState.ackSeqNum, message)
        linkState.ackSent = linkState.ackSeqNum
        val networkMessage = LinkSendMessage(linkState.linkId, oneHopMessage.serialize())
        physicalNetworkActor.tell(networkMessage, self)
    }

    private fun sendTreeForLink(now: Instant, linkId: LinkId) {
        val linkState = linkStates[linkId]
        if (linkState?.identity == null) {
            //log().info("handshake not complete $linkId")
            return
        }
        if (linkState.confirmedSeqNum + linkState.linkCapacity < linkState.seqNum) {
            linkState.linkCapacity = max((linkState.linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
            log().info("link capacity $linkId exhausted skip ${linkState.seqNum} ${linkState.confirmedSeqNum}")
            return
        }
        val parentTree = if (parent == null) null else linkStates[parent!!]?.treeState
        val treeState = TreeState.createTreeState(
            parentTree,
            linkState.receiveSecureId,
            keyService.getVersion(networkId),
            linkState.identity!!,
            keyService,
            now
        )
        //log().info("send ${linkState.linkId} ${linkState.seqNum} ${linkState.ackSeqNum}")
        sendMessageToLink(linkState, treeState)
    }

    private fun sendTreeStatus(now: Instant) {
        val parentTree = if (parent == null) null else linkStates[parent!!]?.treeState
        log().info("tree ${parentTree?.root ?: networkId} ${parentTree?.depth ?: 0}")
        changed = false
        lastSent = now
        for (neighbour in linkStates.values) {
            sendTreeForLink(now, neighbour.linkId)
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

            calcParent()
            sendNeighbourUpdate()
            if (changed) {
                sendTreeStatus(Clock.systemUTC().instant())
            }
        }
    }

    private fun sendHello(linkId: LinkId) {
        //log().info("Send hello message to $linkId")
        val helloMessage = Hello.createHello(networkId, keyService)
        val linkState = LinkState(linkId, helloMessage.secureLinkId)
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
                // do nothing
            }
            else -> log().error("Unknown message type $message")
        }
        val linkState = linkStates[message.linkId]
        if (linkState != null) {
            linkState.ackSeqNum = oneHopMessage.seqNum
            linkState.confirmedSeqNum = oneHopMessage.ackSeqNum
            linkState.linkCapacity++
        }
    }

    private fun processHelloMessage(sourceLink: LinkId, hello: Hello) {
        val linkState = linkStates[sourceLink]
        if (linkState == null) {
            log().error("LinkId not known $sourceLink")
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
            log().info("link from duplicate address closing")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        linkState.identity = hello.sourceId
        linkState.sendSecureId = hello.secureLinkId
        addresses[hello.sourceId.id] = sourceLink
        calcParent()
        sendTreeForLink(Clock.systemUTC().instant(), sourceLink)
    }

    private fun processTreeStateMessage(sourceLink: LinkId, tree: TreeState) {
        //log().info("process tree message")
        val now = Clock.systemUTC().instant()
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
            linkState.linkCapacity = max((linkState.linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
            return
        }
        try {
            tree.verify(linkState.sendSecureId!!, keyService.getVersion(networkId), now)
        } catch (ex: Exception) {
            log().error("Bad Tree message ${ex.message}")
            physicalNetworkActor.tell(CloseRequest(sourceLink), self)
            return
        }
        val neighbour = tree.path.path.last().identity
        if (linkState.identity!!.id != neighbour.id) {
            log().error("Neighbour on $sourceLink doesn't match")
            return
        }
        if (linkState.identity!!.currentVersion.version > neighbour.currentVersion.version) {
            log().error("Neighbour on $sourceLink has stale version")
            return
        }
        linkState.identity = neighbour
        linkState.treeState = tree
        calcParent()
        if (changed || tree.treeAddress != oldState?.treeAddress) {
            sendNeighbourUpdate()
        }
        if (parent == sourceLink) {
            changed = true
        }
        if (changed) {
            sendTreeStatus(now)
        }
    }

    private fun findGreedyNextHop(
        treeAddress: List<SecureHash>,
        sourceLink: LinkId
    ): LinkState? {
        if (treeAddress.first() != selfAddress.first()) {
            val neighbour = addresses[treeAddress.last()]
            if (neighbour != null) {
                return linkStates[neighbour]
            }
            return null
        }

        var best: LinkState? = null
        var bestDistance = Int.MAX_VALUE
        for (neighbourState in linkStates.values) {
            if (neighbourState.linkId != sourceLink
                && neighbourState.identity != null
                && neighbourState.sendSecureId != null
                && neighbourState.treeState != null
                && neighbourState.confirmedSeqNum + neighbourState.linkCapacity + 1 >= neighbourState.seqNum
            ) {
                val neighbourAddress = neighbourState.treeState!!.treeAddress.treeAddress
                var prefixLength = 0
                while (prefixLength < treeAddress.size
                    && prefixLength < neighbourAddress.size
                    && treeAddress[prefixLength] == neighbourAddress[prefixLength]
                ) {
                    ++prefixLength
                }
                val hopCount = treeAddress.size + neighbourAddress.size - 2 * prefixLength + 1
                if (bestDistance >= hopCount) {
                    bestDistance = hopCount
                    best = neighbourState
                }
            }
        }
        return best
    }

    private fun processGreedyRoutedMessage(sourceLink: LinkId, payloadMessage: GreedyRoutedMessage) {
        val now = Clock.systemUTC().instant()
        val linkState = linkStates[sourceLink]
        if (linkState?.identity == null) {
            log().warning("No hello yet received on $sourceLink")
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
            linkState.linkCapacity = max((linkState.linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
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
            val best: LinkState? = findGreedyNextHop(payloadMessage.treeAddress, sourceLink)
            if (best == null) {
                log().warning("No forward route found dropping message to ${payloadMessage.treeAddress} from $selfAddress")
                findGreedyNextHop(payloadMessage.treeAddress, sourceLink)
                return
            }
            if (best.confirmedSeqNum + best.linkCapacity + 2 < best.seqNum) {
                best.linkCapacity = max((best.linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
                log().info("link capacity ${best.linkId} exhausted skip forward ${best.seqNum} ${best.confirmedSeqNum}")
                return
            }
            val forwardMessage = GreedyRoutedMessage.forwardGreedRoutedMessage(
                payloadMessage,
                best.sendSecureId!!,
                keyService.getVersion(networkId),
                best.identity!!,
                keyService,
                now
            )
            sendMessageToLink(best, forwardMessage)
        }
    }

    private fun onSendGreedyMessage(messageRequest: NeighbourSendGreedyMessage) {
        val nextHop = findGreedyNextHop(messageRequest.networkAddress.treeAddress, SimpleLinkId(-1))
        if (nextHop == null) {
            log().warning("Unable to route to ${messageRequest.networkAddress.treeAddress}")
            return
        }
        if (nextHop.confirmedSeqNum + nextHop.linkCapacity + 1 < nextHop.seqNum) {
            nextHop.linkCapacity = max((nextHop.linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
            log().info("link capacity ${nextHop.linkId} exhausted skip greedy send ${nextHop.seqNum} ${nextHop.confirmedSeqNum}")
            return
        }
        val greedyRoutedMessage = GreedyRoutedMessage.createGreedRoutedMessage(
            messageRequest.networkAddress,
            messageRequest.payload,
            nextHop.sendSecureId!!,
            keyService.getVersion(networkId),
            nextHop.identity!!,
            keyService,
            Clock.systemUTC().instant()
        )
        sendMessageToLink(nextHop, greedyRoutedMessage)
    }

    private fun onSendSphinxMessage(messageRequest: NeighbourSendSphinxMessage) {
        val nextHopLink = addresses[messageRequest.nextHop]
        if (nextHopLink == null) {
            log().warning("Unable to route to ${messageRequest.nextHop}")
            return
        }
        val nextHop = linkStates[nextHopLink]
        if (nextHop == null) {
            log().warning("Unable to route to ${messageRequest.nextHop}")
            return
        }
        if (nextHop.confirmedSeqNum + nextHop.linkCapacity + 1 < nextHop.seqNum) {
            nextHop.linkCapacity = max((nextHop.linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
            log().info("link capacity ${nextHop.linkId} exhausted skip sphinx send ${nextHop.seqNum} ${nextHop.confirmedSeqNum}")
            return
        }
        sendMessageToLink(nextHop, messageRequest.message)
    }
}