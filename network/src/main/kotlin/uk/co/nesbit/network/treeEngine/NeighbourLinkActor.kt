package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.routing.Ping
import uk.co.nesbit.network.api.routing.Pong
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.TreeState
import uk.co.nesbit.network.api.tree.TreeStatus
import uk.co.nesbit.network.mocknet.OpenRequest
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.security.SignatureException

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

    private val networkAddress: SphinxPublicIdentity by lazy(LazyThreadSafetyMode.PUBLICATION) {
        keyService.getVersion(networkId).identity
    }

    private val owners = mutableSetOf<ActorRef>()
    private val staticLinkStatus = mutableMapOf<Address, LinkId>()
    private val linkProbes = mutableMapOf<LinkId, Pair<Ping, Boolean>>()
    private val links = mutableMapOf<LinkId, VersionedIdentity>()
    private val addresses = mutableMapOf<SecureHash, LinkId>()
    private var localState: TreeState = TreeState(
        keyService.random.nextLong(),
        null,
        TreeStatus.Isolated,
        listOf(networkAddress)
    )
    private val neighbourStates = mutableMapOf<SecureHash, TreeState>()

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
        sendTreeState()
    }

    private fun sendTreeState() {
        for (neighbour in addresses) {
            val previous = neighbourStates[neighbour.key]
            val treeState = localState.copy(replySeqNo = previous?.currentSeqNo)
            val sendTree = LinkSendMessage(neighbour.value, treeState.serialize())
            physicalNetworkActor.tell(sendTree, self)
        }
    }

    private fun parentState(): TreeState? {
        val parent = localState.parent ?: return null
        val parentState = neighbourStates[parent] ?: return null
        if (parentState.replySeqNo != localState.currentSeqNo) {
            return null
        }
        return parentState
    }

    private fun consistentStates(): List<TreeState> {
        return neighbourStates.values.filter { it.replySeqNo == localState.currentSeqNo }
    }

    private fun canBeRoot(): Boolean {
        return true
    }

    private fun predicateRoot(): Boolean {
        return canBeRoot()
                && localState.status == TreeStatus.Correct
                && localState.pathToRoot == listOf(networkAddress)
    }

    private fun predicateAbnormalRoot(): Boolean {
        val parentState = parentState()
        return !predicateRoot()
                && localState.status != TreeStatus.Isolated
                && (parentState == null
                || TreeState.comparePath(localState.pathToRoot, parentState.pathToRoot + listOf(networkAddress)) > 0
                || (localState.status != parentState.status && parentState.status != TreeStatus.ErrorBroadcast))
    }

    private fun predicateReset(): Boolean {
        return localState.status == TreeStatus.ErrorFeedback
                && predicateAbnormalRoot()
    }

    private fun predicateUpdateNode(): Boolean {
        for (neighbourState in consistentStates()) {
            if (neighbourState.status == TreeStatus.Correct
                && neighbourState.pathToRoot.isNotEmpty()
            ) {
                val comp =
                    TreeState.comparePath(localState.pathToRoot, neighbourState.pathToRoot + listOf(networkAddress))
                if (comp < 0) {
                    return true
                }
            }
        }
        return false
    }

    private fun predicateUpdateRoot(): Boolean {
        return canBeRoot()
                && (TreeState.comparePath(listOf(networkAddress), localState.pathToRoot) > 0)
    }

    private fun predicateNodeImprovement(): Boolean {
        return predicateUpdateNode() || predicateUpdateRoot()
    }

    private fun children(): List<TreeState> {
        return consistentStates().filter {
            it.status != TreeStatus.Isolated
                    && it.parent == networkId
                    && TreeState.comparePath(it.pathToRoot, localState.pathToRoot + it.pathToRoot.last()) >= 0
                    && (it.status == localState.status || localState.status == TreeStatus.ErrorBroadcast)
        }
    }

    private fun beRoot() {
        localState = localState.copy(status = TreeStatus.Correct, pathToRoot = listOf(networkAddress))
    }

    private fun computePath() {
        val correctNeighbours = consistentStates().filter { it.status == TreeStatus.Correct }
        if (correctNeighbours.isNotEmpty()) {
            val bestNeighbour = correctNeighbours.max()!!
            val newPath = bestNeighbour.pathToRoot + listOf(networkAddress)
            localState = localState.copy(status = TreeStatus.Correct, pathToRoot = newPath)
            if (predicateUpdateRoot()) {
                beRoot()
            }
        } else {
            beRoot()
        }
    }

    private fun updateTreeState() {
        if (consistentStates().size == addresses.size) {
            if (localState.status == TreeStatus.Correct && predicateNodeImprovement()) {
                val oldPath = localState.pathToRoot
                computePath()
                log().info("Improve ${localState.pathToRoot.map { it.id }} from ${oldPath.map { it.id }}")
            } else if (localState.status == TreeStatus.Correct
                && !predicateNodeImprovement()
                && (predicateAbnormalRoot() || parentState()?.status == TreeStatus.ErrorBroadcast)
            ) {
                log().error("Bad root")
                localState = localState.copy(status = TreeStatus.ErrorBroadcast)
            } else if (localState.status == TreeStatus.ErrorBroadcast
                && children().all { it.status == TreeStatus.ErrorFeedback }
            ) {
                log().info("Children reset")
                localState = localState.copy(status = TreeStatus.ErrorFeedback)
            } else if (predicateReset() && !canBeRoot() && !consistentStates().any { it.status == TreeStatus.Correct }) {
                log().info("Isolated")
                localState = localState.copy(status = TreeStatus.Isolated)
            } else if ((predicateReset() || localState.status == TreeStatus.Isolated)
                && (canBeRoot() || consistentStates().any { it.status == TreeStatus.Correct })
            ) {
                log().info("Now have valid neighbour")
                computePath()
            }
            localState = localState.copy(currentSeqNo = localState.currentSeqNo + 1L)
            log().info("State ${localState.status} ${localState.pathToRoot.map { it.publicAddress }}")
        }
    }

    private fun onLinkStatusChange(linkInfo: LinkInfo) {
        //log().info("onLinkStatusChange $linkInfo")
        if (linkInfo.status.active) {
            if (linkInfo.route.to in networkConfig.staticRoutes) {
                staticLinkStatus[linkInfo.route.to] = linkInfo.linkId
            }
            sendPing(linkInfo)
        } else {
            staticLinkStatus.remove(linkInfo.route.to)
            linkProbes.remove(linkInfo.linkId)
            val oldAddress = links.remove(linkInfo.linkId)
            if (oldAddress != null) {
                neighbourStates.remove(oldAddress.id)
                addresses.remove(oldAddress.id, linkInfo.linkId)
                for (link in links) {
                    if (link.value.id == oldAddress.id) {
                        addresses[link.value.id] = link.key
                    }
                }
            }
            updateTreeState()
            val update = NeighbourUpdate(keyService.getVersion(networkId), addresses.values.mapNotNull { links[it] })
            for (owner in owners) {
                owner.tell(update, self)
            }
        }
    }

    private fun sendPing(linkInfo: LinkInfo) {
        val ping = Ping.createPing(keyService)
        linkProbes[linkInfo.linkId] = Pair(ping, linkInfo.status == LinkStatus.LINK_UP_ACTIVE)
        val sendPing = LinkSendMessage(linkInfo.linkId, ping.serialize())
        sender.tell(sendPing, self)
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        //log().info("onLinkReceivedMessage $message")
        if (processPing(message)) return
        if (linkProbes.containsKey(message.linkId)) {
            if (processPong(message)) return
        }
        if (processTreeState(message)) return
        val address = links[message.linkId]
        if (address != null) {
            val onwardMessage = NeighbourReceivedMessage(address.identity, message.msg)
            for (owner in owners) {
                owner.tell(onwardMessage, self)
            }
        } else {
            log().warning("Drop message for unlabelled link ${message.linkId}")
        }
    }

    private fun processPing(message: LinkReceivedMessage): Boolean {
        val ping = Ping.tryDeserialize(message.msg)
        if (ping != null) {
            val pong = Pong.createPong(ping, networkId, keyService)
            sender.tell(LinkSendMessage(message.linkId, pong.serialize()), self)
            return true
        }
        return false
    }

    private fun processPong(message: LinkReceivedMessage): Boolean {
        val pong = Pong.tryDeserialize(message.msg)
        if (pong != null) {
            val ping = linkProbes.remove(message.linkId)!!
            try {
                val remoteIdentity = pong.verify(ping.first)
                //log().info("received valid pong on link ${message.linkId} from ${pong.identity}")
                links[message.linkId] = remoteIdentity
                if (!addresses.containsKey(remoteIdentity.id) || ping.second) { // favour active links
                    addresses[remoteIdentity.id] = message.linkId
                }
                val update =
                    NeighbourUpdate(keyService.getVersion(networkId), addresses.values.mapNotNull { links[it] })
                for (owner in owners) {
                    owner.tell(update, self)
                }
            } catch (ex: SignatureException) {
                log().error("Bad Pong signature", ex)
            }
            return true
        }
        return false
    }

    private fun processTreeState(message: LinkReceivedMessage): Boolean {
        val treeState = TreeState.tryDeserialize(message.msg)
        if (treeState != null) {
            val address = links[message.linkId]
            if (address != null) {
                neighbourStates[address.id] = treeState
            }
            updateTreeState()
            return true
        }
        return false
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