package uk.co.nesbit.network.engine

import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.services.NetworkService
import rx.Observable
import rx.subjects.PublishSubject
import java.io.IOException
import java.util.concurrent.LinkedBlockingQueue

class SimNetwork {
    private val networkNodes = mutableMapOf<Address, NetworkServiceImpl>()
    private val messageQueue = LinkedBlockingQueue<Packet>()

    private data class Packet(val route: Route, val viaLinkId: LinkId, val message: Message)

    private class NetworkServiceImpl(val parent: SimNetwork, override val localAddress: Address) : NetworkService {
        companion object {
            var linkIdCounter = 0
        }

        override val links: MutableMap<LinkId, LinkInfo> = mutableMapOf()
        private val addresses = mutableMapOf<Address, LinkId>()

        private val _onReceive = PublishSubject.create<Message>()
        override val onReceive: Observable<Message>
            get() = _onReceive

        private val _onLinkStatusChange = PublishSubject.create<LinkStatusChange>()
        override val onLinkStatusChange: Observable<LinkStatusChange>
            get() = _onLinkStatusChange

        init {
            openLink(localAddress)
        }

        override fun openLink(remoteAddress: Address): Boolean {
            if (addresses.containsKey(remoteAddress)) {
                return false
            }
            val newLink = LinkInfo(SimpleLinkId(linkIdCounter++), RouteState(Route(localAddress, remoteAddress), LinkStatus.LINK_UP))
            links[newLink.linkId] = newLink
            addresses[remoteAddress] = newLink.linkId
            linkChange(LinkStatusChange(newLink.linkId, newLink.state.status))
            return true
        }

        override fun closeLink(linkId: LinkId) {
            val link = links.remove(linkId)
            if (link != null) {
                addresses.remove(link.state.route.to)
                _onLinkStatusChange.onNext(LinkStatusChange(link.linkId, LinkStatus.LINK_DOWN))
                val otherEnd = parent.networkNodes[link.state.route.to]
                if (otherEnd != null) {
                    val reverseLink = otherEnd.findLinkTo(localAddress)
                    if (reverseLink != null) {
                        otherEnd.closeLink(reverseLink)
                    }
                }
            }
        }

        override fun findLinkTo(target: Address): LinkId? = addresses[target]

        override fun send(linkId: LinkId, msg: Message) {
            val link = links[linkId] ?: throw IllegalArgumentException("Invalid LinkId $linkId")
            if (link.state.status != LinkStatus.LINK_UP) {
                throw IOException("Link Unavailable $link")
            }
            parent.messageQueue.offer(Packet(link.state.route, linkId, msg))
        }

        fun deliver(msg: Message) {
            ++parent._messageCount
            _onReceive.onNext(msg)
        }

        fun linkChange(statusChange: LinkStatusChange) {
            val link = links[statusChange.linkId] ?: throw java.lang.IllegalArgumentException("Invalid LinkId $statusChange")
            if (link.state.status != statusChange.status) {
                links[statusChange.linkId] = LinkInfo(link.linkId, state = link.state.copy(status = statusChange.status))
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
        val links1to2 = node1.links.values.filter { it.state.route.to == address2 && it.state.status != status }
        for (link in links1to2) {
            node1.linkChange(LinkStatusChange(link.linkId, status))
        }
        val links2to1 = node1.links.values.filter { it.state.route.to == address1 && it.state.status != status }
        for (link in links2to1) {
            node2.linkChange(LinkStatusChange(link.linkId, status))
        }
    }

    private fun nodeForMessage(packet: Packet?): NetworkServiceImpl? {
        if (packet != null) {
            val sourceNode = networkNodes[packet.route.from]
            if (sourceNode != null) {
                val link = sourceNode.links[packet.viaLinkId]
                if (link != null) {
                    if (link.state.status == LinkStatus.LINK_UP) {
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
        targetNode?.deliver(nextMsg.message)
    }

    fun deliverTillEmpty() {
        while (!messageQueue.isEmpty()) {
            deliverOne()
        }
    }

}