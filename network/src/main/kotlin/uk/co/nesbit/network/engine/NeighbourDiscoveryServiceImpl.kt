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
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class NeighbourDiscoveryServiceImpl(private val networkService: NetworkService,
                                    private val keyService: KeyService) : NeighbourDiscoveryService, AutoCloseable {
    override val networkAddress: SphinxAddress by lazy { SphinxAddress(keyService.getVersion(keyService.generateNetworkID(networkService.networkId.toString())).identity) }

    override val links = ConcurrentHashMap<LinkId, LinkInfo>()
    private val neighbourToLink = ConcurrentHashMap<Address, LinkId>()

    override val knownNeighbours: MutableSet<Address> get() = neighbourToLink.keys

    private val _onLinkStatusChange = PublishSubject.create<LinkInfo>()
    override val onLinkStatusChange: Observable<LinkInfo>
        get() = _onLinkStatusChange

    private val _onReceive = PublishSubject.create<NeighbourReceivedMessage>()
    override val onReceive: Observable<NeighbourReceivedMessage>
        get() = _onReceive

    private val lock = ReentrantLock()
    private val channels = ConcurrentHashMap<LinkId, SecureChannelStateMachine>()
    private var networkLinkSubscription: Disposable? = null

    init {
        networkLinkSubscription = networkService.onLinkStatusChange.subscribe { onLinkChange(it) }
        for (link in networkService.links.values) {
            onLinkChange(link)
        }
    }

    override fun close() {
        networkLinkSubscription?.dispose()
        networkLinkSubscription = null
    }

    override val routes: Routes?
        get() {
            val routes = mutableListOf<SignedEntry>()
            lock.withLock {
                val currentVersion = keyService.getVersion(networkAddress.id)
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
            if (routes.isEmpty()) {
                return null
            }
            return Routes.createRoutes(routes, keyService, networkAddress.id)
        }

    private fun resetLinkInfo(linkId: LinkId): Pair<Boolean, LinkInfo?> {
        val linkInfo = links[linkId]
        if (linkInfo != null) {
            val linkDown = linkInfo.copy(status = LinkStatus.LINK_DOWN)
            links[linkId] = linkDown
            _onLinkStatusChange.onNext(linkDown)
            return Pair(linkInfo.status.active(), linkDown)
        }
        return Pair(false, null)
    }

    private fun onLinkChange(linkChange: LinkInfo) {
        var update: LinkInfo? = null
        lock.withLock {
            when (linkChange.status) {
                LinkStatus.LINK_UP_ACTIVE -> {
                    if (!channels.containsKey(linkChange.linkId)) {
                        val (_, newInfo) = resetLinkInfo(linkChange.linkId)
                        update = newInfo
                        val channel = SecureChannelStateMachine(linkChange.linkId,
                                networkAddress.id,
                                linkChange.route.to,
                                true,
                                _onReceive,
                                keyService,
                                networkService)
                        channels[linkChange.linkId] = channel
                    }
                }
                LinkStatus.LINK_UP_PASSIVE -> {
                    if (!channels.containsKey(linkChange.linkId)) {
                        val (_, newInfo) = resetLinkInfo(linkChange.linkId)
                        update = newInfo
                        val channel = SecureChannelStateMachine(linkChange.linkId,
                                networkAddress.id,
                                linkChange.route.to,
                                false,
                                _onReceive,
                                keyService,
                                networkService)
                        channels[linkChange.linkId] = channel
                    }
                }
                LinkStatus.LINK_DOWN -> {
                    channels[linkChange.linkId]?.close()
                    val (changed, newInfo) = resetLinkInfo(linkChange.linkId)
                    update = newInfo
                    if (changed) {
                        keyService.incrementAndGetVersion(networkAddress.id)
                    }
                }
            }
        }
        if (update != null) {
            _onLinkStatusChange.onNext(update!!)
        }
    }

    override fun findLinkTo(neighbourAddress: Address): LinkId? {
        lock.withLock {
            when (neighbourAddress) {
                is SphinxAddress -> {
                    val linkId = neighbourToLink[neighbourAddress]
                    if (linkId != null) {
                        val linkInfo = links[linkId]
                        if (linkInfo != null) {
                            if (linkInfo.status.active()) {
                                return linkId
                            }
                        }
                    }
                    // Handle race condition where messages start arriving before we have signalled the link is up
                    val channel = channels.values
                            .filter { it.state == SecureChannelStateMachine.ChannelState.SESSION_ACTIVE }
                            .firstOrNull { SphinxAddress(it.remoteID!!.identity) == neighbourAddress }
                    if (channel != null) {
                        return channel.linkId
                    }
                }
                is NetworkAddress -> {
                    val localLink = networkService.addresses[neighbourAddress]
                    if (localLink != null) {
                        val linkInfo = networkService.links[localLink]
                        if (linkInfo != null && linkInfo.status.active()) {
                            return localLink
                        }
                    }
                }
            }
            return null
        }
    }

    override fun send(linkId: LinkId, msg: ByteArray) {
        val ch = lock.withLock {
            val channel = channels[linkId]
            if ((channel == null) || (channel.state != SecureChannelStateMachine.ChannelState.SESSION_ACTIVE)) {
                throw IOException("Link unavailable")
            }
            channel
        }
        ch!!.send(msg)
    }

    override fun runStateMachine() {
        val dropped = mutableListOf<LinkInfo>()
        val opened = mutableListOf<LinkInfo>()
        val errored = mutableListOf<SecureChannelStateMachine>()
        lock.withLock {
            val channelsItr = channels.values.iterator()
            while (channelsItr.hasNext()) {
                val channel = channelsItr.next()
                channel.runStateMachine()
                if (channel.state == SecureChannelStateMachine.ChannelState.ERRORED) {
                    channelsItr.remove()
                    errored += channel
                } else if (channel.state == SecureChannelStateMachine.ChannelState.SESSION_ACTIVE) {
                    val linkInfo = links[channel.linkId]
                    if ((linkInfo == null) || (linkInfo.status == LinkStatus.LINK_DOWN)) {
                        val remoteAddress = SphinxAddress(channel.remoteID!!.identity)
                        val status = if (channel.initiator) LinkStatus.LINK_UP_ACTIVE else LinkStatus.LINK_UP_PASSIVE
                        val oldLink = neighbourToLink.remove(remoteAddress)
                        if (oldLink != null) {
                            links.remove(oldLink)
                        }
                        val newLink = LinkInfo(channel.linkId, Route(networkAddress, remoteAddress), status)
                        links[channel.linkId] = newLink
                        neighbourToLink[remoteAddress] = channel.linkId
                        opened += newLink
                    }
                }
            }
        }
        var versionUpdate = false
        for (channel in errored) {
            val (changed, newInfo) = resetLinkInfo(channel.linkId)
            if (newInfo != null) {
                dropped += newInfo
            }
            if (changed) {
                versionUpdate = true
            }
            val networkLink = networkService.links[channel.linkId]
            if (networkLink != null) {
                networkService.closeLink(networkLink.linkId)
            }
        }
        if (versionUpdate) {
            keyService.incrementAndGetVersion(networkAddress.id)
        }
        for (info in dropped) {
            _onLinkStatusChange.onNext(info)
        }
        for (channel in errored) {
            if (channel.initiator) {
                networkService.openLink(channel.networkTarget)
            }
        }
        for (info in opened) {
            _onLinkStatusChange.onNext(info)
        }
    }
}