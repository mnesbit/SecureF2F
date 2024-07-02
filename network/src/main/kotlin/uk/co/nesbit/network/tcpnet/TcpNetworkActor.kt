package uk.co.nesbit.network.tcpnet

import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.util.concurrent.DefaultThreadFactory
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.netty.tcp.*
import uk.co.nesbit.simpleactor.*
import java.net.InetSocketAddress
import java.time.Clock
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger


class TcpNetworkActor(private val networkConfig: NetworkConfiguration) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, networkConfig)
        }

        val linkIdCounter = AtomicInteger(0)
    }

    private data class ConnectionChange(
        val inbound: Boolean,
        val localAddress: PublicAddress,
        val remoteAddress: PublicAddress,
        val connected: Boolean
    )

    private class InboundMessage(
        val remoteAddress: PublicAddress,
        val message: ByteArray
    )

    private class ClientState(
        val linkId: LinkId,
        val parent: ActorRef,
        target: PublicAddress,
        threads: EventLoopGroup
    ) : TcpMessageListener, TcpConnectListener, AutoCloseable {
        private val tcpClient = TcpClient(
            InetSocketAddress(target.host, target.port),
            TcpClientConfig(false),
            threads,
            true
        )

        private val messageListener = tcpClient.registerMessageListener(this)
        private val eventListener = tcpClient.registerConnectListener(this)
        private var connected = AtomicBoolean(false)
        private val pending = ConcurrentLinkedDeque<ByteArray>()

        init {
            tcpClient.start()
        }

        fun send(message: ByteArray) {
            tcpClient.sendData(message)
        }

        override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
            val local = PublicAddress(localAddress.hostString, localAddress.port)
            val remote = PublicAddress(remoteAddress.hostString, remoteAddress.port)
            parent.tell(ConnectionChange(false, local, remote, true), Actor.NoSender)
            if (!connected.getAndSet(true)) {
                val now = Clock.systemUTC().instant()
                while (true) {
                    val msg = pending.poll() ?: break
                    parent.tell(LinkReceivedMessage(linkId, now, msg), Actor.NoSender)
                }
            }
        }

        override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
            connected.set(false)
            val local = PublicAddress(localAddress.hostString, localAddress.port)
            val remote = PublicAddress(remoteAddress.hostString, remoteAddress.port)
            parent.tell(ConnectionChange(false, local, remote, false), Actor.NoSender)
        }

        override fun onMessage(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress, msg: ByteArray) {
            if (connected.get()) {
                parent.tell(LinkReceivedMessage(linkId, Clock.systemUTC().instant(), msg), Actor.NoSender)
            } else {
                pending += msg
            }
        }

        override fun close() {
            tcpClient.close()
            pending.clear()
            messageListener.close()
            eventListener.close()
        }

    }

    private val networkId: Address get() = networkConfig.networkId
    private val owners = mutableSetOf<ActorRef>()

    private val links = mutableMapOf<LinkId, LinkInfo>()
    private val remoteMapping = mutableMapOf<Address, LinkId>()
    private val clientLinks = mutableMapOf<LinkId, ClientState>()
    private var tcpServer: TcpServer? = null
    private var eventListenerHandle: AutoCloseable? = null
    private var messageListenerHandle: AutoCloseable? = null
    private var clientThreadPool: EventLoopGroup? = null
    private val unmapped = mutableListOf<InboundMessage>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting TcpNetworkActor")
    }

    override fun postStop() {
        stopServer()
        super.postStop()
        //log().info("Stopped TcpNetworkActor")
    }

    override fun preRestart(reason: Throwable, message: Any?) {
        stopServer()
        super.preRestart(reason, message)
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart TcpNetworkActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is WatchRequest -> onWatchRequest()
            is OpenRequest -> onOpenRequest(message)
            is CloseRequest -> onCloseRequest(message)
            is CloseAllRequest -> onCloseAll()
            is ConnectionChange -> onConnectionChange(message)
            is LinkSendMessage -> onLinkSendMessage(message)
            is InboundMessage -> onInboundMessage(message)
            is LinkReceivedMessage -> onLinkReceivedMessage(message)
            is Terminated -> onDeath(message)
            else -> log().warn("Unrecognised message $message")
        }
    }

    private fun startServer() {
        val networkAddress = (networkConfig.bindAddress as PublicAddress)
        val bindAddress = InetSocketAddress(networkAddress.host, networkAddress.port)
        val newServer = TcpServer(bindAddress, TcpServerConfig(false))
        eventListenerHandle = newServer.registerConnectListener(
            object : TcpConnectListener {
                private val selfRef: ActorRef = self

                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    if (networkConfig.denyListedSources.any {
                            (it as PublicAddress).host == remoteAddress.hostString
                                    || it.host == remoteAddress.hostName
                        }) {
                        log().warn("Close connection from denyListed peer $remoteAddress")
                        tcpServer?.closeLink(remoteAddress)
                        return
                    }
                    val local = PublicAddress(localAddress.hostString, localAddress.port)
                    val remote = PublicAddress(remoteAddress.hostString, remoteAddress.port)
                    selfRef.tell(ConnectionChange(true, local, remote, true))
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    val local = PublicAddress(localAddress.hostString, localAddress.port)
                    val remote = PublicAddress(remoteAddress.hostString, remoteAddress.port)
                    selfRef.tell(ConnectionChange(true, local, remote, false))
                }
            }
        )
        messageListenerHandle = newServer.registerMessageListener(
            object : TcpMessageListener {
                private val selfRef: ActorRef = self

                override fun onMessage(
                    localAddress: InetSocketAddress,
                    remoteAddress: InetSocketAddress,
                    msg: ByteArray
                ) {
                    val remote = PublicAddress(remoteAddress.hostString, remoteAddress.port)
                    selfRef.tell(InboundMessage(remote, msg))
                }
            }
        )
        tcpServer = newServer
        clientThreadPool = NioEventLoopGroup(
            2,
            DefaultThreadFactory("TcpClient-$bindAddress", Thread.MAX_PRIORITY)
        )
        try {
            newServer.start()
            log().info("Server listening on $bindAddress")
        } catch (ex: Exception) {
            log().error("Unable to bind to server port ${networkConfig.bindAddress}")
            context.stop(self)
        }
    }

    private fun stopServer() {
        eventListenerHandle?.close()
        eventListenerHandle = null
        messageListenerHandle?.close()
        messageListenerHandle = null
        tcpServer?.close()
        tcpServer = null
        for (client in clientLinks.values) {
            client.close()
        }
        clientLinks.clear()
        clientThreadPool?.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
        clientThreadPool = null
        unmapped.clear()
    }

    private fun onWatchRequest() {
        log().info("WatchRequest from $sender")
        if (tcpServer == null) {
            startServer()
        }
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onDeath(death: Terminated) {
        //log().info("got Terminated $death")
        owners -= death.actor
        if (owners.isEmpty()) {
            stopServer()
        }
    }

    private fun createLink(remoteAddress: Address): LinkId {
        val newLinkId = SimpleLinkId(linkIdCounter.getAndIncrement())
        val newLinkInfo = LinkInfo(newLinkId, Route(networkId, remoteAddress), LinkStatus.LINK_DOWN)
        links[newLinkId] = newLinkInfo
        remoteMapping[remoteAddress] = newLinkId
        return newLinkId
    }

    private fun enableLink(linkId: LinkId, newStatus: LinkStatus) {
        val linkInfo = links[linkId]
        if (linkInfo != null) {
            val newLinkInfo = linkInfo.copy(status = newStatus)
            links[linkId] = newLinkInfo
            if (linkInfo.status != newLinkInfo.status) {
                for (owner in owners) {
                    owner.tell(newLinkInfo, self)
                }
            }
        }
    }

    private fun closeLink(linkId: LinkId) {
        val linkInfo = links[linkId]
        if (linkInfo != null) {
            val newLinkInfo = linkInfo.copy(status = LinkStatus.LINK_DOWN)
            links[linkId] = newLinkInfo
            remoteMapping.remove(linkInfo.route.to)
            val client = clientLinks.remove(linkId)
            client?.close()
            if (linkInfo.status != newLinkInfo.status) {
                for (owner in owners) {
                    owner.tell(newLinkInfo, self)
                }
            }
        }
    }

    private fun onOpenRequest(request: OpenRequest) {
        log().info("OpenRequest $request")
        val linkId = createLink(request.remoteNetworkId)
        if (request.remoteNetworkId !is PublicAddress) {
            val newLinkInfo = links[linkId]!!
            for (owner in owners) {
                owner.tell(newLinkInfo, self)
            }
            return
        }
        clientLinks[linkId] = ClientState(linkId, self, request.remoteNetworkId, clientThreadPool!!)
    }

    private fun onCloseRequest(request: CloseRequest) {
        val link = links[request.linkId]
        log().info("CloseRequest $request $link")
        if (link != null && link.status == LinkStatus.LINK_UP_ACTIVE) {
            val client = clientLinks[request.linkId]
            client?.close()
            closeLink(request.linkId)
        }
        if (link != null && link.status == LinkStatus.LINK_UP_PASSIVE) {
            val remoteAddress = remoteMapping.firstNotNullOfOrNull { if (it.value == request.linkId) it.key else null }
            if (remoteAddress != null) {
                remoteAddress as PublicAddress
                tcpServer?.closeLink(InetSocketAddress(remoteAddress.host, remoteAddress.port))
            }
            closeLink(request.linkId)
        }
    }

    private fun onCloseAll() {
        log().info("CloseAll Request")
        for (linkId in links.keys) {
            onCloseRequest(CloseRequest(linkId))
        }
    }

    private fun onConnectionChange(message: ConnectionChange) {
        if (message.connected) {
            if (message.inbound) {
                val linkId = createLink(message.remoteAddress)
                log().info("Tcp Inbound Connected $message $linkId")
                enableLink(linkId, LinkStatus.LINK_UP_PASSIVE)
                val pendingItr = unmapped.iterator()
                while (pendingItr.hasNext()) {
                    val next = pendingItr.next()
                    if (next.remoteAddress == message.remoteAddress) {
                        pendingItr.remove()
                        onInboundMessage(next)
                    }
                }
            } else {
                val linkId = remoteMapping[message.remoteAddress]
                log().info("Tcp Outbound Connected $message $linkId")
                if (linkId != null) {
                    enableLink(linkId, LinkStatus.LINK_UP_ACTIVE)
                } else {
                    log().warn("Can't resolve ${message.remoteAddress} to linkId")
                }
            }
        } else {
            val linkId = remoteMapping[message.remoteAddress]
            log().warn("Tcp Disconnected $message $linkId")
            if (linkId != null) {
                closeLink(linkId)
                remoteMapping.remove(message.remoteAddress)
            } else {
                log().warn("Can't resolve ${message.remoteAddress} to linkId")
            }
            val pendingItr = unmapped.iterator()
            while (pendingItr.hasNext()) {
                val next = pendingItr.next()
                if (next.remoteAddress == message.remoteAddress) {
                    pendingItr.remove()
                }
            }
        }
    }

    private fun onLinkSendMessage(message: LinkSendMessage) {
        val link = links[message.linkId]
        if (link?.status == LinkStatus.LINK_UP_ACTIVE) {
            val client = clientLinks[link.linkId]
            if (client == null) {
                log().warn("can't send $message")
            }
            client?.send(message.msg)
        } else if (link?.status == LinkStatus.LINK_UP_PASSIVE) {
            val publicAddress = link.route.to as PublicAddress
            val remoteAddress = InetSocketAddress(publicAddress.host, publicAddress.port)
            tcpServer?.sendData(message.msg, remoteAddress)
        }
    }

    private fun onInboundMessage(message: InboundMessage) {
        val linkId = remoteMapping[message.remoteAddress]
        if (linkId != null) {
            if (links[linkId]?.status?.active != true) {
                log().warn("dropping message on $linkId")
                return
            }
            val received = LinkReceivedMessage(linkId, Clock.systemUTC().instant(), message.message)
            for (owner in owners) {
                owner.tell(received, self)
            }
        } else {
            log().warn("Unable to map ${message.remoteAddress} to linkId")
            unmapped += message
        }
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        if (links[message.linkId]?.status?.active != true) {
            log().warn("dropping message on ${message.linkId}")
            return
        }
        for (owner in owners) {
            owner.tell(message, self)
        }
    }

}