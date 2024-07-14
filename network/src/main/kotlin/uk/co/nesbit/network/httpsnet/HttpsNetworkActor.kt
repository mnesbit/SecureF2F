package uk.co.nesbit.network.tcpnet

import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.crypto.toLong
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.PhysicalNetworkActor
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.netty.https.HttpsClientConfig
import uk.co.nesbit.network.netty.https.HttpsClientManager
import uk.co.nesbit.network.netty.https.HttpsServer
import uk.co.nesbit.network.netty.https.HttpsServerConfig
import uk.co.nesbit.simpleactor.*
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.URI
import java.net.URISyntaxException
import java.time.Clock
import kotlin.math.abs


class HttpsNetworkActor(private val networkConfig: NetworkConfiguration, private val keyService: KeyService) :
    AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration, keyService: KeyService): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, networkConfig, keyService)
        }
    }

    private class InboundMessage(
        val source: SocketAddress,
        val target: SocketAddress,
        val uri: URI,
        val bytes: ByteArray
    )

    private val networkId: Address get() = networkConfig.networkId
    private val owners = mutableSetOf<ActorRef>()

    private val links = mutableMapOf<LinkId, LinkInfo>()
    private val linkCookies = mutableMapOf<LinkId, Long>()
    private val reverseLinkCookies = mutableMapOf<Long, LinkId>()
    private var httpsServer: HttpsServer? = null
    private var httpsClients: HttpsClientManager? = null
    private var serverListener: AutoCloseable? = null

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
            is InboundMessage -> onInboundMessage(message)
            is LinkSendMessage -> onLinkSendMessage(message)
            is Terminated -> onDeath(message)
            else -> log().warn("Unrecognised message $message")
        }
    }

    private fun startServer() {
        val networkAddress = (networkConfig.bindAddress as URLAddress)
        val bindAddress = InetSocketAddress(networkAddress.url.host, networkAddress.url.port)
        val newServer = HttpsServer(
            networkAddress.url.host, networkAddress.url.port, HttpsServerConfig(
                networkConfig.keyStore!!,
                networkConfig.trustStore!!
            )
        )
        val newClientManager = HttpsClientManager(HttpsClientConfig(networkConfig.trustStore))
        httpsServer = newServer
        val ownRef = self
        serverListener = newServer.registerMessageListener { source, target, uri, bytes ->
            ownRef.tell(
                InboundMessage(
                    source,
                    target,
                    uri,
                    bytes
                ), Actor.NoSender
            )
        }
        httpsClients = newClientManager
        try {
            newServer.start()
            log().info("Server listening on $bindAddress")
            newClientManager.start()
            log().info("Https client manager started")
        } catch (ex: Exception) {
            log().error("Unable to bind to server port ${networkConfig.bindAddress}")
            context.stop(self)
        }
    }

    private fun stopServer() {
        serverListener?.close()
        serverListener = null
        httpsServer?.close()
        httpsServer = null
        httpsClients?.close()
        httpsClients = null
    }

    private fun onWatchRequest() {
        log().info("WatchRequest from $sender")
        if (httpsServer == null) {
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
        val newLinkId = SimpleLinkId(PhysicalNetworkActor.linkIdCounter.getAndIncrement())
        val newLinkInfo = LinkInfo(newLinkId, Route(networkId, remoteAddress), LinkStatus.LINK_DOWN)
        links[newLinkId] = newLinkInfo
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
        val cookie = linkCookies.remove(linkId)
        if (cookie != null) {
            reverseLinkCookies.remove(cookie)
        }
        if (linkInfo != null) {
            val newLinkInfo = linkInfo.copy(status = LinkStatus.LINK_DOWN)
            links[linkId] = newLinkInfo
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
        if (request.remoteNetworkId !is URLAddress) {
            val newLinkInfo = links[linkId]!!
            for (owner in owners) {
                owner.tell(newLinkInfo, self)
            }
            return
        }
        val targetAddress = request.remoteNetworkId
        val replyAddress = (networkId as URLAddress).url
        val target = targetAddress.url.toURI().resolve("register").toString()
        val cookie = abs(keyService.random.nextLong())
        linkCookies[linkId] = cookie
        reverseLinkCookies[cookie] = linkId
        httpsClients?.sendBytes(
            target,
            concatByteArrays(cookie.toByteArray(), replyAddress.toString().toByteArray(Charsets.UTF_8))
        )
    }

    private fun onCloseAll() {
        log().info("CloseAll Request")
        for (linkId in links.keys) {
            onCloseRequest(CloseRequest(linkId))
        }
    }

    private fun onCloseRequest(request: CloseRequest) {
        val link = links[request.linkId]
        log().info("CloseRequest $request $link")
        if (link != null) {
            val cookie = linkCookies[request.linkId]
            closeLink(request.linkId)
            if (cookie != null) {
                val target = (link.route.to as URLAddress).url.toURI().resolve("unregister").toString()
                httpsClients?.sendBytes(
                    target,
                    cookie.toByteArray()
                )
            }
        }
    }

    private fun onInboundMessage(message: InboundMessage) {
        if (message.uri.path.endsWith("/register")) {
            if (processRegister(message)) return
        } else if (message.uri.path.endsWith("/unregister")) {
            processUnregister(message)
        } else if (message.uri.path.endsWith("/inbox")) {
            processMessage(message)
        } else {
            log().error("Unknown URI used ${message.uri} from ${message.source} to ${message.target}")
        }
    }

    private fun processMessage(message: InboundMessage) {
        if (message.bytes.size < 8) {
            log().info("invalid message")
            return
        }
        val cookie = message.bytes.copyOfRange(0, 8).toLong()
        val linkId = reverseLinkCookies[cookie]
        if (linkId == null) {
            log().warn("Unknown cookie $cookie")
            return
        }
        val linkState = links[linkId]
        if (linkState == null) {
            log().warn("Unknown linkId $linkId")
            return
        }
        if (message.bytes.size == 8) {
            if (linkState.status == LinkStatus.LINK_DOWN) {
                enableLink(linkId, LinkStatus.LINK_UP_ACTIVE)
            } else {
                closeLink(linkId) // Only first message is allowed to be empty, rest is an error
            }
            return
        }
        val received =
            LinkReceivedMessage(linkId, Clock.systemUTC().instant(), message.bytes.copyOfRange(8, message.bytes.size))
        for (owner in owners) {
            owner.tell(received, self)
        }
    }

    private fun processUnregister(message: InboundMessage) {
        if (message.bytes.size != 8) {
            log().info("invalid message")
            return
        }
        val cookie = message.bytes.toLong()
        val linkId = reverseLinkCookies[cookie] ?: return
        closeLink(linkId)
    }

    private fun processRegister(message: InboundMessage): Boolean {
        if (message.bytes.size < 18) {
            log().info("invalid registration")
            return true
        }
        val cookie = message.bytes.copyOfRange(0, 8).toLong()
        val replyAddressStr = String(message.bytes, 8, message.bytes.size - 8, Charsets.UTF_8)
        val uri = try {
            URI(replyAddressStr)
        } catch (ex: URISyntaxException) {
            log().info("invalid registration bad reply address $replyAddressStr")
            return true
        }
        if (uri.scheme != "https") {
            log().info("invalid registration reply address not https $uri")
            return true
        }
        val linkId = createLink(URLAddress(uri.toURL()))
        linkCookies[linkId] = cookie
        reverseLinkCookies[cookie] = linkId
        enableLink(linkId, LinkStatus.LINK_UP_PASSIVE)
        httpsClients?.sendBytes(uri.resolve("inbox").toString(), cookie.toByteArray())
        return false
    }

    private fun onLinkSendMessage(message: LinkSendMessage) {
        val link = links[message.linkId]
        if (link?.status?.active != true) {
            log().info("can't send message on unknown linkId ${message.linkId}")
            return
        }
        val cookie = linkCookies[message.linkId]
        if (cookie == null) {
            log().info("can't send message no cookie for ${message.linkId}")
            return
        }
        val target = (link.route.to as URLAddress).url.toURI().resolve("inbox").toString()
        httpsClients?.sendBytes(
            target,
            concatByteArrays(cookie.toByteArray(), message.msg)
        )
    }

}