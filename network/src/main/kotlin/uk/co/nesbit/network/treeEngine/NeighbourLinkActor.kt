package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.Hello
import uk.co.nesbit.network.api.tree.OneHopMessage
import uk.co.nesbit.network.api.tree.TreeState
import uk.co.nesbit.network.mocknet.CloseRequest
import uk.co.nesbit.network.mocknet.OpenRequest
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit

class NeighbourSendMessage(val networkAddress: SphinxPublicIdentity, val msg: ByteArray)
class NeighbourReceivedMessage(val networkAddress: SphinxPublicIdentity, val msg: ByteArray)
class NeighbourUpdate(val localId: VersionedIdentity, val addresses: List<VersionedIdentity>)

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
        const val MAX_LINK_CAPACITY = 3
    }

    private class CheckStaticLinks(val first: Boolean)
    private class LinkState(
        val linkId: LinkId,
        val receiveSecureId: ByteArray,
        var seqNum: Int = 0,
        var ackSeqNum: Int = -1,
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
            .match(NeighbourSendMessage::class.java, ::onNeighbourSendMessage)
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
                    linkState.treeState = null
                }
            }
            calcParent()
        }
        if (changed) {
            sendTreeStatus(now)
        }
    }

    private fun calcParent() {
        val valid = linkStates.values
            .filter { it.treeState != null }
            .filter { entry -> entry.treeState!!.shortPath.none { it.id == networkId } }
        if (valid.isEmpty()) {
            if (parent != null) {
                parent = null
                changed = true
                lastDepth = 0
            }
            startPoint = 0
            return
        }
        val minRoot = valid.map { it.treeState!!.root }.min()!!
        if (minRoot > networkId) {
            if (parent != null) {
                parent = null
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
                if (parentSeen) {
                    startPoint = j
                }
                break
            }
        }
    }

    private fun sendTreeForLink(now: Instant, linkId: LinkId) {
        val linkState = linkStates[linkId]
        if (linkState?.identity == null) {
            //log().info("handshake not complete $linkId")
            return
        }
        if (linkState.ackSeqNum + MAX_LINK_CAPACITY < linkState.seqNum) {
            //log().info("link capacity $linkId exhausted skip ${linkState.seqNum} ${linkState.ackSeqNum}")
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
        val oneHopMessage = OneHopMessage.createOneHopMessage(linkState.seqNum++, linkState.ackSeqNum, treeState)
        val sendMessage = LinkSendMessage(linkId, oneHopMessage.serialize())
        physicalNetworkActor.tell(sendMessage, self)
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
        val oneHopMessage = OneHopMessage.createOneHopMessage(linkState.seqNum++, linkState.ackSeqNum, helloMessage)
        val networkMessage = LinkSendMessage(linkId, oneHopMessage.serialize())
        physicalNetworkActor.tell(networkMessage, self)
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
            else -> log().error("Unknown message type $message")
        }
        val linkState = linkStates[message.linkId]
        if (linkState != null) {
            linkState.ackSeqNum = oneHopMessage.seqNum
            //log().info("receive ${linkState.linkId} ${linkState.seqNum} ${linkState.ackSeqNum}")
        }

//        val address = links[message.linkId]
//        if (address != null) {
//            val onwardMessage = NeighbourReceivedMessage(address.identity, message.msg)
//            for (owner in owners) {
//                owner.tell(onwardMessage, self)
//            }
//        } else {
//            log().warning("Drop message for unlabelled link ${message.linkId}")
//        }
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
        val linkState = linkStates[sourceLink]
        if (linkState?.identity == null) {
            log().error("No hello yet received on $sourceLink")
            return
        }
        linkState.treeState = null
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
        if (parent == sourceLink) {
            changed = true
        }
        if (changed) {
            sendTreeStatus(now)
        }
    }

    private fun onNeighbourSendMessage(message: NeighbourSendMessage) {
        //log().info("onNeighbourSendMessage $message")
        val linkId = addresses[message.networkAddress.id]
        if (linkId != null) {
            val linkMessage = LinkSendMessage(linkId, message.msg)
            physicalNetworkActor.tell(linkMessage, self)
        } else {
            log().warning("Unable to send message to unknown address ${message.networkAddress}")
        }
    }
}