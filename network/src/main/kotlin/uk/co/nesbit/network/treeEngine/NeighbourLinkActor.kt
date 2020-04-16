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
import uk.co.nesbit.network.mocknet.OpenRequest
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

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
    }

    private class CheckStaticLinks(val first: Boolean)

    private val networkId: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        keyService.generateNetworkID(networkConfig.networkId.toString())
    }

    private val owners = mutableSetOf<ActorRef>()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val addresses = mutableMapOf<SecureHash, LinkId>()
    private val sendSecureLinkIds = mutableMapOf<LinkId, ByteArray>()
    private val receiveSecureLinkIds = mutableMapOf<LinkId, ByteArray>()
    private val links = mutableMapOf<LinkId, VersionedIdentity>()
    private val neighbourState = TreeMap<SecureHash, TreeState>()
    private var parent: SecureHash? = null
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
            timers.startTimerAtFixedRate(
                "staticLinkPoller",
                CheckStaticLinks(false),
                LINK_CHECK_INTERVAL_MS.millis()
            )
        }
        for (expectedLink in networkConfig.staticRoutes) {
            if (!staticLinkStatus.containsKey(expectedLink)) {
                log().info("open static link to $expectedLink")
                physicalNetworkActor.tell(OpenRequest(expectedLink), self)
            }
        }

        calcParent()
        if (changed || ChronoUnit.MILLIS.between(lastSent, Clock.systemUTC().instant()) >= 60000L) {
            sendTreeStatus()
        }
    }

    private fun calcParent() {
        val valid = neighbourState.entries.filter { entry -> entry.value.shortPath.none { it.id == networkId } }
        if (valid.isEmpty()) {
            if (parent != null) {
                parent = null
                changed = true
                lastDepth = 0
            }
            startPoint = 0
            return
        }
        val minRoot = valid.map { it.value.root }.min()!!
        if (minRoot > networkId) {
            if (parent != null) {
                parent = null
                changed = true
                lastDepth = 0
            }
            return
        }
        val withBestRoot = valid.filter { it.value.root == minRoot }
        val minDepth = withBestRoot.map { it.value.depth }.min()!!
        if (lastDepth != minDepth) {
            changed = true
            lastDepth = minDepth
        }
        startPoint = startPoint.rem(withBestRoot.size)
        var parentSeen = false
        for (i in withBestRoot.indices) {
            val j = (i + startPoint).rem(withBestRoot.size)
            if (parent != withBestRoot[j].key) {
                parentSeen = true
            }
            val currentDepth = withBestRoot[j].value.depth
            if (currentDepth == minDepth) {
                if (parent != withBestRoot[j].key) {
                    changed = true
                }
                parent = withBestRoot[j].key
                if (parentSeen) {
                    startPoint = j
                }
                break
            }
        }
    }

    private fun sendTreeStatus() {
        val parentTree = if (parent == null) null else neighbourState[parent!!]
        log().info("tree ${parentTree?.root} ${parentTree?.depth}")
        changed = false
        lastSent = Clock.systemUTC().instant()
        for (neighbour in receiveSecureLinkIds) {
            val neighbourAddress = links[neighbour.key]
            if (neighbourAddress != null) {
                val treeState = TreeState.createTreeState(
                    parentTree,
                    neighbour.value,
                    keyService.getVersion(networkId),
                    neighbourAddress,
                    keyService,
                    Clock.systemUTC()
                )
                val oneHopMessage = OneHopMessage.createOneHopMessage(treeState)
                val sendMessage = LinkSendMessage(neighbour.key, oneHopMessage.serialize())
                physicalNetworkActor.tell(sendMessage, self)
            }
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        //log().info("onLinkStatusChange $linkInfo")
        val linkId = linkInfo.linkId
        if (linkInfo.status.active) {
            if (linkInfo.route.to in networkConfig.staticRoutes) {
                staticLinkStatus[linkInfo.route.to] = linkInfo.linkId
            }
            sendHello(linkInfo)
        } else {
            log().info("Link lost")
            staticLinkStatus.remove(linkInfo.route.to)
            sendSecureLinkIds.remove(linkId)
            receiveSecureLinkIds.remove(linkId)
            val address = links.remove(linkId)
            if (address != null && addresses[address.id] == linkId) {
                addresses.remove(address.id)
                neighbourState.remove(address.id)
                val replacement = links.entries.firstOrNull { it.value.id == address.id }
                if (replacement != null) {
                    addresses[replacement.value.id] = replacement.key
                }
            }
            calcParent()
            if (changed) {
                sendTreeStatus()
            }
        }
    }

    private fun sendHello(linkInfo: LinkInfo) {
        log().info("Send hello message to $linkInfo")
        val helloMessage = Hello.createHello(networkId, keyService)
        sendSecureLinkIds[linkInfo.linkId] = helloMessage.secureLinkId
        val oneHopMessage = OneHopMessage.createOneHopMessage(helloMessage)
        val networkMessage = LinkSendMessage(linkInfo.linkId, oneHopMessage.serialize())
        physicalNetworkActor.tell(networkMessage, self)
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        //log().info("onLinkReceivedMessage $message")
        val payloadMessage = try {
            OneHopMessage.deserializePayload(message.msg)
        } catch (ex: Exception) {
            log().error("Unable to deserialize message ${ex.message}")
            return
        }
        when (payloadMessage) {
            is Hello -> processHelloMessage(message.linkId, payloadMessage)
            is TreeState -> processTreeStateMessage(message.linkId, payloadMessage)
            else -> log().error("Unknown message type $payloadMessage")
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
        try {
            hello.verify()
        } catch (ex: Exception) {
            log().error("Bad Hello message")
            return
        }
        log().info("process hello message")
        receiveSecureLinkIds[sourceLink] = hello.secureLinkId
        links[sourceLink] = hello.sourceId
        if (!addresses.containsKey(hello.sourceId.id)) {
            addresses[hello.sourceId.id] = sourceLink
        }
    }

    private fun processTreeStateMessage(sourceLink: LinkId, tree: TreeState) {
        //log().info("process tree message")
        val secureLinkId = sendSecureLinkIds[sourceLink]
        if (secureLinkId == null) {
            log().error("No secure link id for $sourceLink")
            return
        }
        val expectedNeighbourId = links[sourceLink]
        if (expectedNeighbourId == null) {
            log().error("No valid neighbour for $sourceLink")
            return
        }
        neighbourState.remove(expectedNeighbourId.id)
        try {
            tree.verify(secureLinkId, keyService.getVersion(networkId), Clock.systemUTC())
        } catch (ex: Exception) {
            log().error("Bad Tree message ${ex.message}")
            return
        }
        val neighbour = tree.path.path.last().identity
        if (expectedNeighbourId.id != neighbour.id) {
            log().error("Neighbour on $sourceLink doesn't match")
            return
        }
        if (expectedNeighbourId.currentVersion.version > neighbour.currentVersion.version) {
            log().error("Neighbour on $sourceLink has stale version")
            return
        }
        links[sourceLink] = neighbour
        neighbourState[neighbour.id] = tree
        calcParent()
        if (changed) {
            sendTreeStatus()
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