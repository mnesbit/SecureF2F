package uk.co.nesbit.network.urlnet

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import akka.http.javadsl.Http
import akka.http.javadsl.ServerBinding
import akka.http.javadsl.model.ContentTypes
import akka.http.javadsl.model.HttpEntities
import akka.http.javadsl.model.HttpRequest
import akka.http.javadsl.model.HttpResponse
import akka.pattern.Patterns
import akka.stream.Materializer
import akka.stream.javadsl.Flow
import akka.stream.javadsl.Sink
import akka.util.Timeout
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.api.net.*
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import java.util.concurrent.CompletionStage
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger


class URLNetworkActor(private val networkConfig: NetworkConfiguration) : UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(networkConfig: NetworkConfiguration): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, networkConfig)
        }

        val linkIdCounter = AtomicInteger(0)
    }

    private val networkId: Address get() = networkConfig.networkId
    private val owners = mutableSetOf<ActorRef>()
    private val materializer = Materializer.createMaterializer(context)
    private var serverBinding: ServerBinding? = null

    private val links = mutableMapOf<LinkId, LinkInfo>()

    override fun preStart() {
        super.preStart()
        log().info("Starting URLNetworkActor")
        val networkAddress = (networkConfig.bindAddress as URLAddress)
        val source = Http.get(context.system)
                .newServerAt(networkAddress.url.host, networkAddress.url.port)
                .connectionSource()
        val serverBindingFuture: CompletionStage<ServerBinding> =
                source.to(Sink.foreach { connection ->
                    val flow = Flow.create<HttpRequest>().ask(self, HttpResponse::class.java, Timeout.apply(60L, TimeUnit.SECONDS))
                    connection.handleWith(flow, materializer)
                }
                ).run(materializer)
        Patterns.pipe(serverBindingFuture, context.dispatcher).to(self)
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
            is OpenRequest -> onOpenRequest(message)
            is CloseRequest -> onCloseRequest(message)
            is CloseAllRequest -> onCloseAll()
            is LinkSendMessage -> onLinkSendMessage(message)
            is LinkReceivedMessage -> onLinkReceivedMessage(message)
            is Terminated -> onDeath(message)
            is ServerBinding -> onServerBinding(message)
            is HttpRequest -> onHttpRequest(message)
            else -> log().warning("Unrecognised message $message")
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


    private fun onHttpRequest(message: HttpRequest) {
        log().info("got HttpRequest ${message.method()} ${message.uri}")
        val response = HttpResponse.create()
                .withEntity(HttpEntities.create(ContentTypes.TEXT_HTML_UTF8, "<html><body>Hello world!</body></html>"))
                .withStatus(200)
        message.discardEntityBytes(materializer)
        sender.tell(response, self)
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