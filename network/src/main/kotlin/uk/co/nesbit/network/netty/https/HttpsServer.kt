package uk.co.nesbit.network.netty.https

import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpServerCodec
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.handler.ssl.SslHandler
import io.netty.handler.timeout.IdleStateHandler
import io.netty.util.concurrent.DefaultThreadFactory
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import uk.co.nesbit.crypto.contextLogger
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.network.api.LifeCycle
import uk.co.nesbit.network.netty.NettyServerEventLogger
import java.net.BindException
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.URI
import java.util.concurrent.*
import java.util.concurrent.locks.ReentrantLock
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import kotlin.concurrent.withLock

class HttpsServer(
    val bindAddress: String,
    val port: Int,
    val config: HttpsServerConfig
) : LifeCycle {
    private val lock = ReentrantLock()
    private var bossGroup: EventLoopGroup? = null
    private var workerGroup: EventLoopGroup? = null
    private var sslDelegatedTaskExecutor: ExecutorService? = null
    private var serverChannel: Channel? = null
    private val clientChannels = ConcurrentHashMap<InetSocketAddress, SocketChannel>()
    private val listeners = ConcurrentLinkedQueue<ListenerEntry>()


    companion object {
        init {
            InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
        }

        const val SERVER_IDLE_TIME_SECONDS = 60
        const val MAX_CONTENT_LENGTH = 1048576
        private val log = contextLogger()
    }

    private class ListenerEntry(
        val parent: HttpsServer,
        val listener: HttpsServerMessageListener
    ) : AutoCloseable, HttpsServerMessageListener {
        override fun close() {
            parent.listeners.remove(this)
        }

        override fun onMessage(source: SocketAddress, target: SocketAddress, uri: URI, msg: ByteArray) {
            listener.onMessage(source, target, uri, msg)
        }
    }

    private class ServerChannelInitializer(val parent: HttpsServer) : ChannelInitializer<SocketChannel>() {
        private val keyManagerFactory: KeyManagerFactory =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        private val trustManagerFactory: TrustManagerFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        private val conf = parent.config

        init {
            keyManagerFactory.init(conf.keyStore.keystore, parent.config.keyStore.entryPassword?.toCharArray())
            trustManagerFactory.init(conf.trustStore)
        }

        private fun createServerSslHandler(delegateTaskExecutor: Executor): SslHandler {
            val sslContext = SSLContext.getInstance("TLS")
            val trustManagers = trustManagerFactory
                .trustManagers
                ?.map { if (it is X509ExtendedTrustManager) LoggingTrustManagerWrapper(it) else it }
                ?.toTypedArray()

            sslContext.init(keyManagerFactory.keyManagers, trustManagers, newSecureRandom())

            val sslEngine = sslContext.createSSLEngine()
            sslEngine.useClientMode = false
            sslEngine.needClientAuth = false
            sslEngine.enabledProtocols = arrayOf("TLSv1.3")
            sslEngine.enabledCipherSuites = arrayOf("TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384")
            sslEngine.enableSessionCreation = true
            return SslHandler(sslEngine, false, delegateTaskExecutor)
        }

        override fun initChannel(ch: SocketChannel) {
            val pipeline = ch.pipeline()
            val taskHandler = parent.sslDelegatedTaskExecutor!!
            val sslHandler = createServerSslHandler(taskHandler)
            pipeline.addLast("sslHandler", sslHandler)
            if (conf.trace) pipeline.addLast("logger", LoggingHandler(LogLevel.INFO))
            pipeline.addLast("idleStateHandler", IdleStateHandler(0, 0, SERVER_IDLE_TIME_SECONDS))
            pipeline.addLast(HttpServerCodec())
            pipeline.addLast(HttpObjectAggregator(MAX_CONTENT_LENGTH))
            pipeline.addLast(
                HttpsServerChannelHandler(
                    object : ChannelConnectionListener {
                        override fun onOpen(channel: SocketChannel) {
                            parent.clientChannels[channel.remoteAddress()] = channel
                        }

                        override fun onClose(channel: SocketChannel) {
                            val remoteAddress = channel.remoteAddress()
                            parent.clientChannels.remove(remoteAddress)
                        }
                    },
                    { source, target, uri, msg ->
                        for (listener in parent.listeners) {
                            listener.onMessage(source, target, uri, msg)
                        }
                    },
                    log,
                    parent.config.uriMap
                )
            )
        }
    }

    fun registerMessageListener(listener: HttpsServerMessageListener): AutoCloseable {
        val entry = ListenerEntry(this, listener)
        listeners += entry
        return entry
    }

    override fun start() {
        lock.withLock {
            sslDelegatedTaskExecutor =
                namedThreadPoolExecutor(maxPoolSize = 3, poolName = "HttpsServer-$bindAddress:$port-ssltask")
            bossGroup =
                NioEventLoopGroup(1, DefaultThreadFactory("HttpServer-$bindAddress:$port-boss", Thread.MAX_PRIORITY))
            workerGroup = NioEventLoopGroup(
                4,
                DefaultThreadFactory("HttpServer-$bindAddress:$port-worker", Thread.MAX_PRIORITY)
            )

            val server = ServerBootstrap()

            server.group(bossGroup, workerGroup).channel(NioServerSocketChannel::class.java)
                .option(ChannelOption.SO_BACKLOG, 100)
                .handler(NettyServerEventLogger(LogLevel.INFO))
                .childHandler(ServerChannelInitializer(this))

            log.info("Try to bind $port")
            val channelFuture = server.bind(bindAddress, port)
                .sync() // block/throw here as better to know we failed to claim port than carry on
            if (!channelFuture.isDone || !channelFuture.isSuccess) {
                throw BindException("Failed to bind port $port")
            }
            log.info("Listening on port $port")
            serverChannel = channelFuture.channel()

        }
    }

    override fun close() {
        lock.withLock {
            listeners.clear()

            serverChannel?.close()
            serverChannel = null

            workerGroup?.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
            workerGroup?.terminationFuture()?.sync()
            workerGroup = null

            bossGroup?.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
            bossGroup?.terminationFuture()?.sync()
            bossGroup = null

            sslDelegatedTaskExecutor?.shutdown()
            sslDelegatedTaskExecutor = null
        }
    }

}