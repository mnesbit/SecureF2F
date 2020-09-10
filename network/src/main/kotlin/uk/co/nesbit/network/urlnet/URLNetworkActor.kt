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
        const val STALE_CHECK_INTERVAL = 1000L
        const val MAX_BUFFER_SIZE = 100
        const val BATCH_SIZE = 10
        const val COOKIE_NAME = "link-id"
    }

    private class HttpRequestAndSource(
        val source: InetSocketAddress,
        val request: HttpRequest
    )

    private class CheckStaleLinks(val first: Boolean)

    private data class BindResult(val success: ServerBinding?, val error: Throwable? = null)

    private data class OpenResponse(
        val open: OpenRequest,
        val linkId: LinkId,
        val response: HttpResponse,
        val error: Throwable? = null
    )

    private data class SendMailResponse(
        val linkId: LinkId,
        val response: HttpResponse,
        val error: Throwable? = null
    )

    private data class MailGetResponse(
        val linkId: LinkId,
        val response: HttpResponse,
        val error: Throwable? = null
    )

    private data class ConnectionInfo(
        val linkId: LinkId,
        val cookieString: String,
        var refreshed: Instant,
    ) {
        var opened: Boolean = false
        val packets = mutableListOf<ByteArray>()
    }

    private data class ClientConnectionInfo(
        val linkId: LinkId,
        val baseUri: Uri,
        var refreshed: Instant = Clock.systemUTC().instant(),
    ) {
        var pendingGet: Boolean = false
        var pendingSend: Boolean = false
        var cookie: Cookie? = null
        val packets = mutableListOf<ByteArray>()
    }

    private class SendMailBodyContext(
        val context: ConnectionInfo,
        val source: ActorRef,
        val error: Throwable? = null
    ) {
        private var body: ByteString = ByteString.emptyByteString()

        fun concat(part: ByteString): SendMailBodyContext {
            body = body.concat(part)
            return this
        }

        fun toBodyString(): String {
            return body.decodeString(Charsets.UTF_8)
        }
    }

    private class GetMailBodyContext(
        val context: ClientConnectionInfo,
        val source: ActorRef,
        val error: Throwable? = null
    ) {
        private var body: ByteString = ByteString.emptyByteString()

        fun concat(part: ByteString): GetMailBodyContext {
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
    private val serverLinkInfo = mutableMapOf<String, ConnectionInfo>()
    private val serverReverseLinkInfo = mutableMapOf<LinkId, ConnectionInfo>()
    private val clientLinkInfo = mutableMapOf<LinkId, ClientConnectionInfo>()

    override fun preStart() {
        super.preStart()
        log().info("Starting URLNetworkActor")
        val networkAddress = (networkConfig.bindAddress as URLAddress)
        val source = Http.get(context.system)
            .newServerAt(networkAddress.url.host, networkAddress.url.port)
            .connectionSource()
        val serverBindingFuture: CompletionStage<BindResult> =
            source.to(Sink.foreach { connection ->
                val flow = Flow.create<HttpRequest>()
                    .map { HttpRequestAndSource(connection.remoteAddress(), it) }
                    .ask(self, HttpResponse::class.java, Timeout.apply(60L, TimeUnit.SECONDS))
                connection.handleWith(flow, materializer)
            }
            ).run(materializer)
                .thenApply { BindResult(it) }
                .exceptionally { error -> BindResult(null, error) }
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
            is OpenResponse -> onOpenResponse(message)
            is CloseRequest -> onCloseRequest(message)
            is CloseAllRequest -> onCloseAll()
            is LinkSendMessage -> onLinkSendMessage(message)
            is SendMailResponse -> onLinkSendResponse(message)
            is Terminated -> onDeath(message)
            is BindResult -> onServerBinding(message)
            is HttpRequestAndSource -> onHttpRequest(message)
            is SendMailBodyContext -> onSendMailReceivedBody(message)
            is MailGetResponse -> onMailGetResponse(message)
            is GetMailBodyContext -> onMailGetReceivedBody(message)
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
        val connectionItr = serverLinkInfo.iterator()
        while (connectionItr.hasNext()) {
            val link = connectionItr.next().value
            if (ChronoUnit.MILLIS.between(link.refreshed, now) >= LINK_HEARTBEAT_INTERVAL) {
                connectionItr.remove()
                serverReverseLinkInfo.remove(link.linkId)
                log().info("remove stale link $link")
                closeLink(link.linkId)
            }
        }
        val clientConnectionItr = clientLinkInfo.iterator()
        while (clientConnectionItr.hasNext()) {
            val link = clientConnectionItr.next()
            if (ChronoUnit.MILLIS.between(link.value.refreshed, now) >= LINK_HEARTBEAT_INTERVAL) {
                connectionItr.remove()
                log().info("remove stale link $link")
                closeLink(link.value.linkId)
            } else if (!link.value.pendingGet) {
                getMail(link.key, BATCH_SIZE)
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

    private fun onServerBinding(message: BindResult) {
        if (message.error != null) {
            log().error(message.error.cause, "Failed to bind")
            context.stop(self)
            return
        }
        serverBinding = message.success
        log().info("Got ServerBinding to ${serverBinding!!.localAddress()}")
    }

    private fun onHttpRequest(message: HttpRequestAndSource) {
        val request = message.request
        //log().info("got HttpRequest ${message.source} ${request.method()} ${request.uri}")
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
                return serverLinkInfo[linkCookieValue]
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
        val connectionInfo = ConnectionInfo(newLink, cookieString, now)
        serverLinkInfo[cookieString] = connectionInfo
        serverReverseLinkInfo[newLink] = connectionInfo
        //log().info("Send new cookie $connectionInfo")
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
            .runFold(SendMailBodyContext(connectionInfo, sender), { acc, b -> acc.concat(b) }, materializer)
            .exceptionally { error -> SendMailBodyContext(connectionInfo, sender, error) }
        Patterns.pipe(content, context.dispatcher).to(self)
        return null
    }

    private fun onSendMailReceivedBody(message: SendMailBodyContext) {
        if (message.error != null) {
            log().error("mail send failed ${message.error.message}")
            val errorReply = HttpResponse.create().withStatus(StatusCodes.INTERNAL_SERVER_ERROR)
            message.source.tell(errorReply, self)
            return
        }
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
        //log().info("sendmail payload = $payload")
        val adapter = moshi.adapter(MessageStatus::class.java)
        try {
            val mail = adapter.fromJson(payload)
            for (packet in mail!!.messages) {
                onLinkReceivedMessage(LinkReceivedMessage(message.context.linkId, now, packet.bytes))
            }
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
        val linkStatus = links[connectionInfo.linkId]
        if (linkStatus == null) {
            serverReverseLinkInfo.remove(connectionInfo.linkId)
            serverLinkInfo.remove(connectionInfo.cookieString)
            return sendErrorResponse(message, StatusCodes.NOT_FOUND)
        }
        message.request.discardEntityBytes(materializer)
        if (!connectionInfo.opened || !linkStatus.status.active) {
            enableLink(linkStatus.linkId, LinkStatus.LINK_UP_PASSIVE)
            connectionInfo.opened = true
        }
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
        //log().info("OpenRequest $request")
        val linkId = createLink(request.remoteNetworkId)
        if (request.remoteNetworkId !is URLAddress) {
            val newLinkInfo = links[linkId]!!
            for (owner in owners) {
                owner.tell(newLinkInfo, self)
            }
            return
        }
        val requestBase = Uri.create(request.remoteNetworkId.url.toString())
        clientLinkInfo[linkId] = ClientConnectionInfo(linkId, requestBase)
        val requestTarget = requestBase.addPathSegment("connect")
        val openRequest = HttpRequest.create()
            .withUri(requestTarget)
            .withMethod(HttpMethods.POST)
            .withHeaders(listOf(Accept.create(MediaRanges.create(MediaTypes.APPLICATION_JSON))))
        val connectFuture = Http.get(context.system)
            .singleRequest(openRequest)
            .thenApply { response -> OpenResponse(request, linkId, response) }
            .exceptionally { error ->
                OpenResponse(
                    request,
                    linkId,
                    HttpResponse.create().withStatus(StatusCodes.NOT_FOUND),
                    error
                )
            }

        Patterns.pipe(connectFuture, context.dispatcher).to(self)
    }

    private fun onOpenResponse(message: OpenResponse) {
        val link = clientLinkInfo[message.linkId] ?: return
        val linkInfo = links[message.linkId]
        if (linkInfo == null) {
            message.response.discardEntityBytes(materializer)
            clientLinkInfo.remove(message.linkId)
            return
        }
        if (message.error != null
            || message.response.status().isFailure
        ) {
            log().error("link open failed $message")
            message.response.discardEntityBytes(materializer)
            clientLinkInfo.remove(message.linkId)
            for (owner in owners) {
                owner.tell(linkInfo, self)
            }
            return
        }
        val cookie = message.response.getHeader(SetCookie::class.java)
        if (cookie.isEmpty || cookie.get().cookie().name() != COOKIE_NAME) {
            log().error("Response missing set-Cookie header")
            clientLinkInfo.remove(message.linkId)
            closeLink(message.linkId)
            return
        }
        message.response.discardEntityBytes(materializer)
        val httpCookie = cookie.get().cookie()
        link.cookie = Cookie.create(httpCookie.name(), httpCookie.value())
        link.refreshed = Clock.systemUTC().instant()
        enableLink(message.linkId, LinkStatus.LINK_UP_ACTIVE)
        getMail(message.linkId, BATCH_SIZE)
    }

    private fun getMail(linkId: LinkId, batchSize: Int) {
        val linkInfo = clientLinkInfo[linkId] ?: return
        val link = links[linkId]
        if (link == null) {
            clientLinkInfo.remove(linkId)
            return
        }
        if (linkInfo.cookie == null) {
            return
        }
        linkInfo.pendingGet = true
        val requestTarget = linkInfo.baseUri
            .addPathSegment("getmail")
            .query(Query.create(akka.japi.Pair.create("maxMessages", batchSize.toString())))
        val headers = listOf(
            Accept.create(MediaRanges.create(MediaTypes.APPLICATION_JSON)),
            linkInfo.cookie!!
        )
        val getMailRequest = HttpRequest.create()
            .withUri(requestTarget)
            .withMethod(HttpMethods.POST)
            .withHeaders(headers)
        val connectFuture = Http.get(context.system)
            .singleRequest(getMailRequest)
            .thenApply { response -> MailGetResponse(linkId, response) }
            .exceptionally { error ->
                MailGetResponse(
                    linkId,
                    HttpResponse.create().withStatus(StatusCodes.NOT_FOUND),
                    error
                )
            }

        Patterns.pipe(connectFuture, context.dispatcher).to(self)
    }

    private fun onMailGetResponse(message: MailGetResponse) {
        val link = clientLinkInfo[message.linkId] ?: return
        if (links[message.linkId] == null) {
            message.response.discardEntityBytes(materializer)
            clientLinkInfo.remove(message.linkId)
            return
        }
        if (message.error != null
            || message.response.status().isFailure
        ) {
            log().error("link mail get failed $message")
            message.response.discardEntityBytes(materializer)
            clientLinkInfo.remove(message.linkId)
            closeLink(message.linkId)
            return
        }
        val content = message.response.entity().dataBytes
            .runFold(GetMailBodyContext(link, sender), { acc, b -> acc.concat(b) }, materializer)
            .exceptionally { error -> GetMailBodyContext(link, sender, error) }
        Patterns.pipe(content, context.dispatcher).to(self)
    }

    private fun onMailGetReceivedBody(message: GetMailBodyContext) {
        message.context.pendingGet = false
        if (message.error != null) {
            log().error("mail get failed ${message.error.message}")
            return
        }
        val linkStatus = links[message.context.linkId]
        if (linkStatus == null || !linkStatus.status.active) {
            return
        }
        val now = Clock.systemUTC().instant()
        val payload = message.toBodyString()
        //log().info("getmail payload = $payload")
        val adapter = moshi.adapter(MessageStatus::class.java)
        try {
            val mail = adapter.fromJson(payload)
            for (packet in mail!!.messages) {
                onLinkReceivedMessage(LinkReceivedMessage(linkStatus.linkId, now, packet.bytes))
            }
            if (mail.messagesRemaining > 0) {
                getMail(message.context.linkId, minOf(mail.messagesRemaining + BATCH_SIZE, MAX_BUFFER_SIZE))
            }
        } catch (ex: Exception) {
            log().error("unable to read packets")
            return
        }
        message.context.refreshed = now
    }

    private fun onCloseRequest(request: CloseRequest) {
        log().info("CloseRequest $request ${links[request.linkId]}")
        clientLinkInfo.remove(request.linkId)
        val serverInfo = serverReverseLinkInfo.remove(request.linkId)
        if (serverInfo != null) {
            serverLinkInfo.remove(serverInfo.cookieString)
        }
        closeLink(request.linkId)
    }

    private fun onCloseAll() {
        log().info("CloseAll Request")
        clientLinkInfo.clear()
        serverLinkInfo.clear()
        serverReverseLinkInfo.clear()
        for (link in links.values) {
            closeLink(link.linkId)
        }
    }

    private fun onLinkSendMessage(request: LinkSendMessage) {
        //log().info("onLinkSendMessage to ${request.linkId}")
        val link = links[request.linkId] ?: return
        if (link.status == LinkStatus.LINK_UP_PASSIVE) {
            val linkInfo = serverReverseLinkInfo[request.linkId]
            if (linkInfo != null) {
                if (linkInfo.packets.size > MAX_BUFFER_SIZE) {
                    log().warning("drop packets on ${request.linkId} due to full buffer")
                    sender.tell(LinkSendStatus(request.linkId, false), self)
                    return
                }
                linkInfo.packets += request.msg
                sender.tell(LinkSendStatus(request.linkId, true), self)
            }
        } else if (link.status == LinkStatus.LINK_UP_ACTIVE) {
            val linkInfo = clientLinkInfo[request.linkId]
            if (linkInfo?.cookie != null) {
                if (linkInfo.packets.size < MAX_BUFFER_SIZE) {
                    linkInfo.packets += request.msg
                    sender.tell(LinkSendStatus(request.linkId, true), self)
                } else {
                    log().warning("drop packets on ${request.linkId} due to full buffer")
                    sender.tell(LinkSendStatus(request.linkId, false), self)
                }
                if (!linkInfo.pendingSend) {
                    sendMail(linkInfo)
                }
            }
        }
    }

    private fun sendMail(
        linkInfo: ClientConnectionInfo
    ) {
        if (linkInfo.packets.isEmpty()) {
            linkInfo.pendingSend = false
            return
        }
        linkInfo.pendingSend = true
        val requestTarget = linkInfo.baseUri.addPathSegment("sendmail")
        val mailMessage = MessageStatus.create(linkInfo.packets, BATCH_SIZE)
        val adaptor = moshi.adapter(MessageStatus::class.java)
        val json = adaptor.toJson(mailMessage)
        val headers = listOf(
            Accept.create(MediaRanges.create(MediaTypes.APPLICATION_JSON)),
            linkInfo.cookie!!
        )
        val sendMailRequest = HttpRequest.create()
            .withUri(requestTarget)
            .withMethod(HttpMethods.POST)
            .withHeaders(headers)
            .withEntity(ContentTypes.APPLICATION_JSON, json)
        val connectFuture = Http.get(context.system)
            .singleRequest(sendMailRequest)
            .thenApply { response -> SendMailResponse(linkInfo.linkId, response) }
            .exceptionally { error ->
                SendMailResponse(
                    linkInfo.linkId,
                    HttpResponse.create().withStatus(StatusCodes.NOT_FOUND),
                    error
                )
            }

        Patterns.pipe(connectFuture, context.dispatcher).to(self)
    }

    private fun onLinkSendResponse(response: SendMailResponse) {
        response.response.discardEntityBytes(materializer)
        val link = clientLinkInfo[response.linkId] ?: return
        if (links[response.linkId] == null) {
            response.response.discardEntityBytes(materializer)
            clientLinkInfo.remove(response.linkId)
            return
        }
        link.pendingSend = false
        if (response.error != null
            || response.response.status().isFailure
        ) {
            log().error("send mail get failed $response")
            response.response.discardEntityBytes(materializer)
            clientLinkInfo.remove(response.linkId)
            closeLink(response.linkId)
            return
        }
        response.response.discardEntityBytes(materializer)
        link.refreshed = Clock.systemUTC().instant()
        if (link.packets.isNotEmpty()) {
            sendMail(link)
        }
    }

    private fun onLinkReceivedMessage(message: LinkReceivedMessage) {
        //log().info("send link received ${message.linkId}")
        for (owner in owners) {
            owner.tell(message, self)
        }
    }
}