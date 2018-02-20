package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.subjects.PublishSubject
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.services.LinkReceivedMessage
import uk.co.nesbit.network.api.services.NetworkService
import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue

class SimNetwork {
    private val networkNodes = mutableMapOf<Address, NetworkServiceImpl>()
    private val messageQueue = LinkedBlockingQueue<Packet>()

    private class Packet(val route: Route, val viaLinkId: LinkId, val message: ByteArray)

    private class NetworkServiceImpl(val parent: SimNetwork, override val networkId: Address) : NetworkService {
        companion object {
            var linkIdCounter = 0
        }

        override val links: MutableMap<LinkId, LinkInfo> = mutableMapOf()
        val addresses = mutableMapOf<Address, LinkId>()
        private val linkToAddress = mutableMapOf<LinkId, Address>()

        private val _onReceive = PublishSubject.create<LinkReceivedMessage>()
        override val onReceive: Observable<LinkReceivedMessage>
            get() = _onReceive

        private val _onLinkStatusChange = PublishSubject.create<LinkStatusChange>()
        override val onLinkStatusChange: Observable<LinkStatusChange>
            get() = _onLinkStatusChange

        private fun linkOpenedByRemote(remoteAddress: Address) {
            if (addresses.containsKey(remoteAddress)) {
                return
            }
            val newLink = SimpleLinkId(linkIdCounter++)
            val linkInfo = LinkInfo(newLink, RouteState(Route(networkId, remoteAddress), LinkStatus.LINK_UP_PASSIVE))
            links[newLink] = linkInfo
            linkToAddress[newLink] = remoteAddress
            addresses[remoteAddress] = newLink
            _onLinkStatusChange.onNext(LinkStatusChange(newLink, linkInfo.state.status))
        }

        override fun openLink(remoteAddress: Address): Boolean {
            if (addresses.containsKey(remoteAddress)) {
                return false
            }
            val newLink = SimpleLinkId(linkIdCounter++)
            val linkInfo = LinkInfo(newLink, RouteState(Route(networkId, remoteAddress), LinkStatus.LINK_UP_ACTIVE))
            links[newLink] = linkInfo
            linkToAddress[newLink] = remoteAddress
            addresses[remoteAddress] = newLink
            parent.networkNodes[remoteAddress]?.linkOpenedByRemote(networkId)
            _onLinkStatusChange.onNext(LinkStatusChange(newLink, linkInfo.state.status))
            return true
        }

        override fun closeLink(linkId: LinkId) {
            val link = links.remove(linkId)
            if (link != null) {
                val linkAddress = linkToAddress.remove(linkId)
                addresses.remove(linkAddress)
                _onLinkStatusChange.onNext(LinkStatusChange(linkId, LinkStatus.LINK_DOWN))
                val otherEnd = parent.networkNodes[linkAddress]
                if (otherEnd != null) {
                    val reverseLink = otherEnd.addresses[networkId]
                    if (reverseLink != null) {
                        otherEnd.closeLink(reverseLink)
                    }
                }
            }
        }

        override fun send(linkId: LinkId, msg: ByteArray) {
            val linkInfo = links[linkId] ?: throw IllegalArgumentException("Invalid LinkId $linkId")
            if (!linkInfo.state.status.active()) {
                throw IOException("Link Unavailable $linkId")
            }
            parent.messageQueue.offer(Packet(Route(networkId, linkToAddress[linkId]!!), linkId, msg))
        }

        fun deliver(msg: LinkReceivedMessage) {
            ++parent._messageCount
            _onReceive.onNext(msg)
        }

        fun linkChange(statusChange: LinkStatusChange) {
            val currentInfo = links[statusChange.linkId]
                    ?: throw java.lang.IllegalArgumentException("Invalid LinkId $statusChange")
            if (currentInfo.state.status != statusChange.status) {
                links[statusChange.linkId] = LinkInfo(currentInfo.linkId, RouteState(currentInfo.state.route, statusChange.status))
                _onLinkStatusChange.onNext(statusChange)
            }
        }
    }

    private var _messageCount = 0L
    val messageCount: Long get() = _messageCount

    fun getNetworkService(id: Address): NetworkService {
        return networkNodes.getOrPut(id) { NetworkServiceImpl(this, id) }
    }

    fun changeLinkStatus(address1: Address, address2: Address, status: LinkStatus) {
        val node1 = networkNodes[address1] ?: throw IllegalArgumentException("Unknown node $address1")
        val node2 = networkNodes[address2] ?: throw IllegalArgumentException("Unknown node $address2")
        val link12Id = node1.addresses[address2]
        node1.linkChange(LinkStatusChange(link12Id!!, status))
        val link21Id = node2.addresses[address1]
        node2.linkChange(LinkStatusChange(link21Id!!, status))
    }

    private fun nodeForMessage(packet: Packet?): NetworkServiceImpl? {
        if (packet != null) {
            val sourceNode = networkNodes[packet.route.from]
            if (sourceNode != null) {
                val status = sourceNode.links[packet.viaLinkId]
                if (status != null) {
                    if (status.state.status.active()) {
                        return networkNodes[packet.route.to]
                    }
                }
            }
        }
        return null
    }

    fun deliverOne() {
        val nextMsg = messageQueue.poll()
        val targetNode = nodeForMessage(nextMsg)
        if (targetNode != null) {
            val receivingLinkId = targetNode.addresses[nextMsg.route.from]
            if (receivingLinkId != null) {
                targetNode.deliver(LinkReceivedMessage(receivingLinkId, nextMsg.message))
            }
        }
    }

    fun shuffleMessages() {
        val reorderList = mutableListOf<Packet>()
        messageQueue.drainTo(reorderList)
        reorderList.shuffle()
        messageQueue.addAll(reorderList)
    }

    fun deliverTillEmpty() {
        while (!messageQueue.isEmpty()) {
            deliverOne()
        }
    }

}