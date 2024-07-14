package uk.co.nesbit.network.netty.https

import io.netty.bootstrap.Bootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.codec.http.*
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.handler.ssl.SslHandler
import io.netty.handler.timeout.IdleStateHandler
import io.netty.util.concurrent.DefaultThreadFactory
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import uk.co.nesbit.crypto.contextLogger
import uk.co.nesbit.crypto.debug
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.network.api.LifeCycle
import java.net.URI
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import kotlin.concurrent.withLock

class HttpsClient(
    val targetAddress: String,
    val targetPort: Int,
    val config: HttpsClientConfig,
    private val workerGroup: EventLoopGroup,
    private val sslDelegatedTaskExecutor: ExecutorService,
    private val shared: Boolean = true
) : LifeCycle {

    constructor(
        targetAddress: String,
        targetPort: Int,
        config: HttpsClientConfig
    ) : this(
        targetAddress,
        targetPort,
        config,
        NioEventLoopGroup(
            NUM_CLIENT_THREADS,
            DefaultThreadFactory("HttpsClient-$targetAddress:$targetPort", Thread.MAX_PRIORITY)
        ),
        namedThreadPoolExecutor(maxPoolSize = 2, poolName = "HttpsClient-$targetAddress:$targetPort-ssltask"),
        false
    )

    private val lock = ReentrantLock()
    private val listeners = ConcurrentLinkedQueue<ListenerEntry>()
    private val pendingSends = ConcurrentLinkedQueue<QueuedPacket>()

    @Volatile
    private var clientChannel: SocketChannel? = null

    @Volatile
    private var retries = 0

    @Volatile
    private var closing = false

    private val connectListener = ChannelFutureListener { future ->
        if (!future.isSuccess) {
            logger.warn("Failed to connect to $targetAddress:$targetPort: ${future.cause().message} ${future.cause().javaClass.name}")
            if (retries++ < MAX_RETRIES && !closing) {
                workerGroup.schedule(
                    {
                        connect()
                    },
                    RETRY_INTERVAL,
                    TimeUnit.MILLISECONDS
                )
            } else {
                logger.warn("Not retrying $targetAddress:$targetPort")
                for (listener in listeners) {
                    listener.onDisconnected()
                }
            }
        } else {
            logger.debug { "Connected to $targetAddress:$targetPort" }
        }
    }

    companion object {
        init {
            InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
        }

        const val NUM_CLIENT_THREADS = 2
        const val MAX_RETRIES = 2
        const val RETRY_INTERVAL = 1000L
        const val MAX_CONTENT_LENGTH = 1048576
        private val log = contextLogger()
    }

    private class ListenerEntry(
        val parent: HttpsClient,
        val listener: HttpsClientListener
    ) : AutoCloseable {
        override fun close() {
            parent.listeners.remove(this)
        }

        fun onConnected() {
            listener.onConnected(parent)
        }

        fun onDisconnected() {
            listener.onDisconnected(parent)
        }
    }

    private class QueuedPacket(
        val packet: ByteArray,
        val path: String,
        val contentType: CharSequence
    )

    private class ClientChannelInitializer(val parent: HttpsClient) : ChannelInitializer<SocketChannel>() {
        private val trustManagerFactory: TrustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        private val conf = parent.config

        init {
            trustManagerFactory.init(conf.trustStore)
        }

        private fun createClientSslHandler(delegateTaskExecutor: Executor): SslHandler {
            val sslContext = SSLContext.getInstance("TLS")
            val trustManagers = trustManagerFactory
                .trustManagers
                ?.map { if (it is X509ExtendedTrustManager) LoggingTrustManagerWrapper(it) else it }
                ?.toTypedArray()

            sslContext.init(null, trustManagers, newSecureRandom())

            val sslEngine = sslContext.createSSLEngine(parent.targetAddress, parent.targetPort)
            sslEngine.useClientMode = true
            sslEngine.needClientAuth = false
            sslEngine.enabledProtocols = arrayOf("TLSv1.3")
            sslEngine.enabledCipherSuites = arrayOf("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384")
            sslEngine.enableSessionCreation = true
            val sslParameters = sslEngine.sslParameters
            sslParameters.endpointIdentificationAlgorithm = "HTTPS"
            sslEngine.sslParameters = sslParameters
            return SslHandler(sslEngine, false, delegateTaskExecutor)
        }

        override fun initChannel(ch: SocketChannel) {
            val pipeline = ch.pipeline()
            val taskHandler = parent.sslDelegatedTaskExecutor
            val sslHandler = createClientSslHandler(taskHandler)
            pipeline.addLast("sslHandler", sslHandler)
            if (conf.trace) pipeline.addLast("logger", LoggingHandler(LogLevel.INFO))
            pipeline.addLast("idleStateHandler", IdleStateHandler(0, 0, HttpsServer.SERVER_IDLE_TIME_SECONDS))
            pipeline.addLast(HttpClientCodec())
            pipeline.addLast(HttpObjectAggregator(MAX_CONTENT_LENGTH))
            pipeline.addLast(
                HttpsClientChannelHandler(
                    object : ChannelConnectionListener {
                        override fun onOpen(channel: SocketChannel) {
                            parent.clientChannel = channel
                            while (parent.pendingSends.isNotEmpty()) {
                                val packet = parent.pendingSends.poll()
                                if (packet != null) {
                                    parent.sendData(packet.packet, packet.path, packet.contentType)
                                }
                            }
                            for (listener in parent.listeners) {
                                listener.onConnected()
                            }
                        }

                        override fun onClose(channel: SocketChannel) {
                            parent.clientChannel = null
                            for (listener in parent.listeners) {
                                listener.onDisconnected()
                            }
                        }
                    },
                    log
                )
            )
        }
    }

    fun registerClientListener(listener: HttpsClientListener): AutoCloseable {
        val listenerEntry = ListenerEntry(this, listener)
        listeners += listenerEntry
        return listenerEntry
    }

    override fun start() {
        lock.withLock {
            connect()
        }
    }

    private fun connect() {
        if (closing) {
            return
        }
        val bootstrap = Bootstrap()
        bootstrap.group(workerGroup).channel(NioSocketChannel::class.java).handler(ClientChannelInitializer(this))
        val clientFuture = bootstrap.connect(targetAddress, targetPort)
        clientFuture.addListener(connectListener)
    }

    override fun close() {
        lock.withLock {
            closing = true
            clientChannel?.close()?.sync()
            clientChannel = null
            if (!shared) {
                workerGroup.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
                workerGroup.terminationFuture()?.sync()

                sslDelegatedTaskExecutor.shutdown()
            }
            listeners.clear()
        }
    }

    fun sendData(packet: ByteArray, path: String, contentType: CharSequence) {
        if (closing) {
            return
        }
        if (clientChannel != null) {
            val content = Unpooled.copiedBuffer(packet)
            val url = URI("https", null, targetAddress, targetPort, path, null, null).toURL()
            val httpPacket = DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1,
                HttpMethod.POST,
                url.toString(),
                content
            ).apply {
                headers()
                    .set(HttpHeaderNames.HOST, targetAddress)
                    .set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE)
                    .set(HttpHeaderNames.ACCEPT_ENCODING, HttpHeaderValues.APPLICATION_JSON)
                    .set(HttpHeaderNames.CONTENT_TYPE, contentType)
                    .set(HttpHeaderNames.CONTENT_LENGTH, content().readableBytes())
            }
            clientChannel?.writeAndFlush(httpPacket)
        } else {
            pendingSends += QueuedPacket(packet.copyOf(), path, contentType)
        }
    }
}