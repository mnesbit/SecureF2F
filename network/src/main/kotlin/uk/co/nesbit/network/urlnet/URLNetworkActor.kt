package uk.co.nesbit.network.urlnet

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import akka.http.javadsl.Http
import akka.http.javadsl.ServerBinding
import akka.http.javadsl.model.*
import akka.http.javadsl.model.headers.Accept
import akka.http.javadsl.model.headers.Cookie
import akka.http.javadsl.model.headers.HttpCookie
import akka.http.javadsl.model.headers.SetCookie
import akka.pattern.Patterns
import akka.stream.Materializer
import akka.stream.javadsl.Flow
import akka.stream.javadsl.Sink
import akka.util.ByteString
import akka.util.Timeout
import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.InstantTimeAdapter
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.net.InetSocketAddress
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import java.util.concurrent.CompletionStage
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class URLNetworkActor(private val networkConfig: NetworkConfiguration, private val keyService: KeyService) :
    UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration, keyService: KeyService): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, networkConfig, keyService)
        }

        val linkIdCounter = AtomicInteger(0)

        const val LINK_HEARTBEAT_INTERVAL = 60000L
        const val STALE_CHECK_INTERVAL = LINK_HEARTBEAT_INTERVAL / 2L
        const val COOKIE_NAME = "link-id"
    }

    private class HttpRequestAndSource(
        val source: InetSocketAddress,
        val request: HttpRequest
    )

    private class CheckStaleLinks(val first: Boolean)

    private data class ConnectionInfo(
        val linkId: LinkId,
        var refreshed: Instant,
        var opened: Boolean = false
    ) {
        val packets = mutableListOf<ByteArray>()
    }

    private class BodyContext(
        val context: ConnectionInfo,
        val source: ActorRef
    ) {
        private var body: ByteString = ByteString.emptyByteString()

        fun concat(part: ByteString): BodyContext {
            body = body.concat(part)
            return this
        }

        fun toBodyString(): String {
            return body.decodeString(Charsets.UTF_8)
        }
    }

    @JsonClass(generateAdapter = true)
    internal class StatusInfo(
        val ok: Boolean,
        val now: Instant = Clock.systemUTC().instant()
    )

    @JsonClass(generateAdapter = true)
    internal class MessageEnvelope(val data: String) {
        constructor(bytes: ByteArray) : this(Base64.getEncoder().encodeToString(bytes))

        val bytes: ByteArray by lazy(LazyThreadSafetyMode.PUBLICATION) {
            Base64.getDecoder().decode(data)
        }
    }

    @JsonClass(generateAdapter = true)
    internal class MessageStatus(
        val messages: List<MessageEnvelope>,
        val messagesRemaining: Int
    ) {
        companion object {
            fun create(packets: MutableList<ByteArray>, maxPackets: Int): MessageStatus {
                val messages = mutableListOf<MessageEnvelope>()
                var count = 0
                while (count < maxPackets && packets.isNotEmpty()) {
                    messages += MessageEnvelope(packets.removeAt(0))
                    ++count
                }
                return MessageStatus(messages, packets.size)
            }
        }
    }

    private val networkId: Address get() = networkConfig.networkId
    private val owners = mutableSetOf<ActorRef>()
    private val materializer = Materializer.createMaterializer(context)
    private val moshi = Moshi.Builder().add(InstantTimeAdapter).build()
    private var serverBinding: ServerBinding? = null

    private val links = mutableMapOf<LinkId, LinkInfo>()
    private val linkCookies = mutableMapOf<String, ConnectionInfo>()

    override fun preStart() {
        super.preStart()
        log().info("Starting URLNetworkActor")
        val networkAddress = (networkConfig.bindAddress as URLAddress)
        val source = Http.get(context.system)
            .newServerAt(networkAddress.url.host, networkAddress.url.port)
            .connectionSource()
        val serverBindingFuture: CompletionStage<ServerBinding> =
            source.to(Sink.foreach { connection ->
                val flow = Flow.create<HttpRequest>()
                    .map { HttpRequestAndSource(connection.remoteAddress(), it) }
                    .ask(self, HttpResponse::class.java, Timeout.apply(60L, TimeUnit.SECONDS))
                connection.handleWith(flow, materializer)
            }
            ).run(materializer)
        Patterns.pipe(serverBindingFuture, context.dispatcher).to(self)

        timers.startSingleTimer(
            "staleLinkCheckStartup",
            CheckStaleLinks(true),
            STALE_CHECK_INTERVAL.millis()
        )

    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped URLNetworkActor")
        serverBinding?.unbind()
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart URLNetworkActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is WatchRequest -> onWatchRequest()
            is CheckStaleLinks -> onCheckStaleLinks(message)
            is OpenRequest -> onOpenRequest(message)
            is CloseRequest -> onCloseRequest(message)
            is CloseAllRequest -> onCloseAll()
            is LinkSendMessage -> onLinkSendMessage(message)
            is LinkReceivedMessage -> onLinkReceivedMessage(message)
            is Terminated -> onDeath(message)
            is ServerBinding -> onServerBinding(message)
            is HttpRequestAndSource -> onHttpRequest(message)
            is BodyContext -> onMessageCompleted(message)
            else -> log().warning("Unrecognised message $message")
        }
    }

    private fun onCheckStaleLinks(message: CheckStaleLinks) {
        if (message.first) {
            timers.startTimerWithFixedDelay(
                "staleLinkCheckStartup",
                CheckStaleLinks(false),
                STALE_CHECK_INTERVAL.millis()
            )
        }
        val now = Clock.systemUTC().instant()
        val connectionItr = linkCookies.iterator()
        while (connectionItr.hasNext()) {
            val link = connectionItr.next().value
            if (ChronoUnit.MILLIS.between(link.refreshed, now) >= LINK_HEARTBEAT_INTERVAL) {
                connectionItr.remove()
                log().info("remove stale link $link")
                closeLink(link.linkId)
            }
        }
    }

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onDeath(death: Terminated) {
        //log().info("got Terminated $death")
        owners -= death.actor
    }

    private fun onServerBinding(message: ServerBinding) {
        log().info("Got ServerBinding to ${message.localAddress()}")
        serverBinding = message
    }


    private fun onHttpRequest(message: HttpRequestAndSource) {
        val request = message.request
        log().info("got HttpRequest ${message.source} ${request.method()} ${request.uri}")
        val reply: HttpResponse? = when (request.method()) {
            HttpMethods.GET -> {
                processHttpGet(message)
            }
            HttpMethods.POST -> {
                processHttpPost(message)
            }
            else -> sendErrorResponse(message, StatusCodes.METHOD_NOT_ALLOWED)
        }
        if (reply != null) {
            sender.tell(reply, self)
        }
    }

    private fun sendErrorResponse(message: HttpRequestAndSource, status: StatusCode): HttpResponse {
        message.request.discardEntityBytes(materializer)
        return HttpResponse.create()
            .withStatus(status)
    }

    private fun getLinkInformation(message: HttpRequestAndSource): ConnectionInfo? {
        val cookieOpt = message.request.getHeader(Cookie::class.java)
        if (cookieOpt.isPresent) {
            val cookie = cookieOpt.get()
            val linkCookie = cookie.cookies.firstOrNull { it.name() == COOKIE_NAME }
            if (linkCookie != null) {
                val linkCookieValue = linkCookie.value()
                return linkCookies[linkCookieValue]
            }
        }
        return null
    }

    private fun processHttpGet(message: HttpRequestAndSource): HttpResponse {
        if (!message.request.entity().isKnownEmpty) {
            return sendErrorResponse(message, StatusCodes.UNPROCESSABLE_ENTITY)
        }
        return when (message.request.uri.path()) {
            "/link/status" -> processGetStatus(message)
            else -> sendErrorResponse(message, StatusCodes.NOT_FOUND)
        }
    }

    private fun processGetStatus(message: HttpRequestAndSource): HttpResponse {
        val connectionInfo = getLinkInformation(message)
        if (connectionInfo != null) {
            connectionInfo.refreshed = Clock.systemUTC().instant()
            log().info("refresh link $connectionInfo")
        }
        val accept = message.request.getHeader(Accept::class.java)
        if (accept.isEmpty || !accept.get().mediaRanges.contains(MediaRanges.create(MediaTypes.APPLICATION_JSON))) {
            return sendErrorResponse(message, StatusCodes.UNSUPPORTED_MEDIA_TYPE)
        }
        message.request.discardEntityBytes(materializer)
        val status = StatusInfo(true)
        val adaptor = moshi.adapter(StatusInfo::class.java)
        val json = adaptor.toJson(status)
        return HttpResponse.create()
            .withEntity(HttpEntities.create(ContentTypes.APPLICATION_JSON, json))
            .withStatus(StatusCodes.OK)
    }

    private fun processHttpPost(message: HttpRequestAndSource): HttpResponse? {
        return when (message.request.uri.path()) {
            "/link/connect" -> processConnectRequest(message)
            "/link/sendmail" -> processMessageDelivery(message)
            "/link/getmail" -> processGetMessages(message)
            else -> sendErrorResponse(message, StatusCodes.NOT_FOUND)
        }
    }

    private fun processConnectRequest(message: HttpRequestAndSource): HttpResponse {
        if (!message.request.entity().isKnownEmpty) {
            return sendErrorResponse(message, StatusCodes.UNPROCESSABLE_ENTITY)
        }
        val accept = message.request.getHeader(Accept::class.java)
        if (accept.isEmpty || !accept.get().mediaRanges.contains(MediaRanges.create(MediaTypes.APPLICATION_JSON))) {
            return sendErrorResponse(message, StatusCodes.UNSUPPORTED_MEDIA_TYPE)
        }
        val newLink = createLink(PublicAddress(message.source.hostName, message.source.port))
        val randomBytes = ByteArray(16)
        keyService.random.nextBytes(randomBytes)
        val cookieString = Base64.getEncoder().encodeToString(randomBytes)
        val cookie = HttpCookie.create(COOKIE_NAME, cookieString)
        val now = Clock.systemUTC().instant()
        val connectionInfo = ConnectionInfo(newLink, now)
        linkCookies[cookieString] = connectionInfo
        log().info("Send new cookie $connectionInfo")
        val status = StatusInfo(true, now)
        val adaptor = moshi.adapter(StatusInfo::class.java)
        val json = adaptor.toJson(status)
        message.request.discardEntityBytes(materializer)
        return HttpResponse.create()
            .withHeaders(listOf(SetCookie.create(cookie)))
            .withEntity(json)
            .withStatus(StatusCodes.OK)
    }

    private fun processMessageDelivery(message: HttpRequestAndSource): HttpResponse? {
        if (message.request.entity().isKnownEmpty) {
            return sendErrorResponse(message, StatusCodes.UNPROCESSABLE_ENTITY)
        }
        if (message.request.entity().contentType != ContentTypes.APPLICATION_JSON) {
            return sendErrorResponse(message, StatusCodes.UNSUPPORTED_MEDIA_TYPE)
        }
        val accept = message.request.getHeader(Accept::class.java)
        if (accept.isEmpty || !accept.get().mediaRanges.contains(MediaRanges.create(MediaTypes.APPLICATION_JSON))) {
            return sendErrorResponse(message, StatusCodes.UNSUPPORTED_MEDIA_TYPE)
        }
        val connectionInfo = getLinkInformation(message) ?: return sendErrorResponse(message, StatusCodes.NOT_FOUND)
        val content = message.request.entity().dataBytes
            .runFold(BodyContext(connectionInfo, sender), { acc, b -> acc.concat(b) }, materializer)
        Patterns.pipe(content, context.dispatcher).to(self)
        return null
    }

    private fun onMessageCompleted(message: BodyContext) {
        val linkStatus = links[message.context.linkId]
        if (!message.context.opened) {
            if (linkStatus == null) {
                val errorReply = HttpResponse.create().withStatus(StatusCodes.NOT_FOUND)
                message.source.tell(errorReply, self)
                return
            }
            enableLink(linkStatus.linkId, LinkStatus.LINK_UP_PASSIVE)
            message.context.opened = true
        } else if (linkStatus == null || !linkStatus.status.active) {
            val errorReply = HttpResponse.create().withStatus(StatusCodes.NOT_FOUND)
            message.source.tell(errorReply, self)
            return
        }
        val now = Clock.systemUTC().instant()
        val payload = message.toBodyString()
        log().info("payload = $payload")
        val adapter = moshi.adapter(MessageEnvelope::class.java)
        try {
            val mail = adapter.fromJson(payload)
            val bytes = mail!!.bytes
            onLinkReceivedMessage(LinkReceivedMessage(message.context.linkId, now, bytes))
        } catch (ex: Exception) {
            log().error("unable to read packet")
            val errorReply = HttpResponse.create().withStatus(StatusCodes.UNPROCESSABLE_ENTITY)
            message.source.tell(errorReply, self)
            return
        }
        message.context.refreshed = now
        val status = StatusInfo(true, now)
        val adaptor = moshi.adapter(StatusInfo::class.java)
        val json = adaptor.toJson(status)
        val reply = HttpResponse.create()
            .withEntity(json)
            .withStatus(StatusCodes.OK)
        message.source.tell(reply, self)
    }

    private fun processGetMessages(message: HttpRequestAndSource): HttpResponse {
        if (!message.request.entity().isKnownEmpty) {
            return sendErrorResponse(message, StatusCodes.UNPROCESSABLE_ENTITY)
        }
        val accept = message.request.getHeader(Accept::class.java)
        if (accept.isEmpty || !accept.get().mediaRanges.contains(MediaRanges.create(MediaTypes.APPLICATION_JSON))) {
            return sendErrorResponse(message, StatusCodes.UNSUPPORTED_MEDIA_TYPE)
        }
        val maxPacketsQuery = message.request.uri.query().get("maxMessages")
        if (maxPacketsQuery.isEmpty) {
            return sendErrorResponse(message, StatusCodes.BAD_REQUEST)
        }
        val maxPackets = try {
            maxPacketsQuery.get().toInt()
        } catch (ex: Exception) {
            return sendErrorResponse(message, StatusCodes.BAD_REQUEST)
        }
        val connectionInfo = getLinkInformation(message) ?: return sendErrorResponse(message, StatusCodes.NOT_FOUND)
        val messages = MessageStatus.create(connectionInfo.packets, maxPackets)
        val adapter = moshi.adapter(MessageStatus::class.java)
        val json = adapter.toJson(messages)
        return HttpResponse.create()
            .withEntity(json)
            .withStatus(StatusCodes.OK)
    }


    private fun createLink(remoteAddress: Address): LinkId {
        val newLinkId = SimpleLinkId(linkIdCounter.getAndIncrement())
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
    }

    private fun onCloseRequest(request: CloseRequest) {
        log().info("CloseRequest $request ${links[request.linkId]}")
    }

    private fun onCloseAll() {
        log().info("CloseAll Request")
    }

    private fun onLinkSendMessage(message: LinkSendMessage) {
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        for (owner in owners) {
            owner.tell(message, self)
        }
    }
}