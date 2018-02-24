package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.disposables.Disposable
import io.reactivex.subjects.PublishSubject
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.routing.Routes
import uk.co.nesbit.network.api.routing.SignedEntry
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.NeighbourDiscoveryService
import uk.co.nesbit.network.api.services.NeighbourReceivedMessage
import uk.co.nesbit.network.api.services.NetworkService
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class NeighbourDiscoveryServiceImpl(val networkService: NetworkService,
                                    val keyService: KeyService) : NeighbourDiscoveryService, AutoCloseable {
    override val networkAddress: SphinxAddress by lazy { SphinxAddress(keyService.getVersion(keyService.networkId).identity) }

    override val links: MutableMap<LinkId, LinkInfo> = mutableMapOf()
    private val neighbourToLink: MutableMap<Address, LinkId> = mutableMapOf()

    override val knownNeighbours: MutableSet<Address> get() = neighbourToLink.keys

    private val _onLinkStatusChange = PublishSubject.create<LinkStatusChange>()
    override val onLinkStatusChange: Observable<LinkStatusChange>
        get() = _onLinkStatusChange

    private val _onReceive = PublishSubject.create<NeighbourReceivedMessage>()
    override val onReceive: Observable<NeighbourReceivedMessage>
        get() = _onReceive

    private val lock = ReentrantLock()
    private val channels = mutableMapOf<LinkId, SecureChannelStateMachine>()
    private var networkLinkSubscription: Disposable? = null

    init {
        networkLinkSubscription = networkService.onLinkStatusChange.subscribe { onLinkChange(it) }
        for (link in networkService.links) {
            onLinkChange(LinkStatusChange(link.key, link.value.state.status))
        }
    }

    override fun close() {
        networkLinkSubscription?.dispose()
        networkLinkSubscription = null
    }

    override val routes: Routes
        get() {
            val routes = mutableListOf<SignedEntry>()
            lock.withLock {
                val currentVersion = keyService.getVersion(keyService.networkId)
                for (channel in channels.values) {
                    if (channel.state == SecureChannelStateMachine.ChannelState.SESSION_ACTIVE) {
                        val routeEntry = channel.routeEntry
                        if (routeEntry != null) {
                            val (version, route) = routeEntry
                            if (version == currentVersion.currentVersion.version) {
                                routes += route
                            }
                        }
                    }
                }
            }
            return Routes.createRoutes(routes, keyService)
        }

    private fun resetLinkInfo(linkId: LinkId): Boolean {
        val linkInfo = links[linkId]
        if (linkInfo != null) {
            links[linkId] = LinkInfo(linkId, linkInfo.state.copy(status = LinkStatus.LINK_DOWN))
            return linkInfo.state.status.active()
        }
        return false
    }

    private fun onLinkChange(linkStatusChange: LinkStatusChange) {
        lock.withLock {
            when (linkStatusChange.status) {
                LinkStatus.LINK_UP_ACTIVE -> {
                    if (!channels.containsKey(linkStatusChange.linkId)) {
                        resetLinkInfo(linkStatusChange.linkId)
                        val channel = SecureChannelStateMachine(linkStatusChange.linkId, true, keyService, networkService)
                        channels[linkStatusChange.linkId] = channel
                        channel.onReceive.subscribe(_onReceive)
                    }
                }
                LinkStatus.LINK_UP_PASSIVE -> {
                    if (!channels.containsKey(linkStatusChange.linkId)) {
                        resetLinkInfo(linkStatusChange.linkId)
                        val channel = SecureChannelStateMachine(linkStatusChange.linkId, false, keyService, networkService)
                        channels[linkStatusChange.linkId] = channel
                        channel.onReceive.subscribe(_onReceive)
                    }
                }
                LinkStatus.LINK_DOWN -> {
                    val channel = channels.remove(linkStatusChange.linkId)
                    channel?.close()
                    if (resetLinkInfo(linkStatusChange.linkId)) {
                        keyService.incrementAndGetVersion(keyService.networkId)
                    }
                    _onLinkStatusChange.onNext(linkStatusChange)
                }
            }
        }
    }

    override fun findLinkTo(neighbourAddress: Address): LinkId? {
        val linkId = neighbourToLink[neighbourAddress]
        if (linkId != null) {
            val linkInfo = links[linkId]
            if (linkInfo != null) {
                if (linkInfo.state.status.active()) {
                    return linkId
                }
            }
        }
        return null
    }

    override fun send(linkId: LinkId, msg: ByteArray) {
        val ch = lock.withLock {
            val channel = channels[linkId]
            if ((channel == null) || (channel.state != SecureChannelStateMachine.ChannelState.SESSION_ACTIVE)) {
                return
            }
            channel
        }
        ch?.send(msg)
    }

    override fun runStateMachine() {
        lock.withLock {
            val errored = mutableListOf<LinkId>()
            val channelsItr = channels.values.iterator()
            while (channelsItr.hasNext()) {
                val channel = channelsItr.next()
                channel.runStateMachine()
                if (channel.state == SecureChannelStateMachine.ChannelState.ERRORED) {
                    channelsItr.remove()
                    errored += channel.linkId
                } else if (channel.state == SecureChannelStateMachine.ChannelState.SESSION_ACTIVE) {
                    val linkInfo = links[channel.linkId]
                    if ((linkInfo == null) || (linkInfo.state.status == LinkStatus.LINK_DOWN)) {
                        val localAddress = SphinxAddress(keyService.getVersion(keyService.networkId).identity)
                        val remoteAddress = SphinxAddress(channel.remoteID!!.identity)
                        val status = if (channel.initiator) LinkStatus.LINK_UP_ACTIVE else LinkStatus.LINK_UP_PASSIVE
                        val oldLink = neighbourToLink.remove(remoteAddress)
                        if (oldLink != null) {
                            links.remove(oldLink)
                        }
                        links[channel.linkId] = LinkInfo(channel.linkId, RouteState(Route(localAddress, remoteAddress), status))
                        neighbourToLink[remoteAddress] = channel.linkId
                        _onLinkStatusChange.onNext(LinkStatusChange(channel.linkId, status))
                    }
                }
            }
            var versionUpdate = false
            for (linkId in errored) {
                if (resetLinkInfo(linkId)) {
                    versionUpdate = true
                }
            }
            if (versionUpdate) {
                keyService.incrementAndGetVersion(keyService.networkId)
            }
            for (linkId in errored) {
                resetLinkInfo(linkId)
                _onLinkStatusChange.onNext(LinkStatusChange(linkId, LinkStatus.LINK_DOWN))
                val networkLink = networkService.links[linkId]
                if (networkLink != null) {
                    if (networkLink.state.status == LinkStatus.LINK_UP_ACTIVE) {
                        networkService.closeLink(linkId)
                        networkService.openLink(networkLink.state.route.to)
                    } else if (networkLink.state.status == LinkStatus.LINK_UP_PASSIVE) {
                        networkService.closeLink(linkId)
                    }
                }
            }
        }
    }
}