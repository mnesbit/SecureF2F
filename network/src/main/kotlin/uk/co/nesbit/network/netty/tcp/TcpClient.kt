package uk.co.nesbit.network.netty.tcp

import io.netty.bootstrap.Bootstrap
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.codec.LengthFieldBasedFrameDecoder
import io.netty.handler.codec.LengthFieldPrepender
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.util.concurrent.DefaultThreadFactory
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import uk.co.nesbit.crypto.contextLogger
import uk.co.nesbit.network.api.LifeCycle
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class TcpClient(
    val target: InetSocketAddress,
    val config: TcpClientConfig,
    private val workerGroup: EventLoopGroup,
    private val shared: Boolean = true
) : LifeCycle {

    constructor(
        target: InetSocketAddress,
        config: TcpClientConfig
    ) : this(
        target,
        config,
        NioEventLoopGroup(
            NUM_CLIENT_THREADS,
            DefaultThreadFactory("TcpClient-$target", Thread.MAX_PRIORITY)
        ),
        false
    )

    private val lock = ReentrantLock()
    private val connectListeners = ConcurrentLinkedQueue<ConnectListenerEntry>()
    private val listeners = ConcurrentLinkedQueue<MessageListenerEntry>()
    private val pendingSends = ConcurrentLinkedQueue<ByteArray>()

    @Volatile
    private var clientChannel: SocketChannel? = null

    @Volatile
    private var retries = 0

    @Volatile
    private var closing = false

    private val connectListener = ChannelFutureListener { future ->
        if (!future.isSuccess) {
            log.warn("Failed to connect to $target: ${future.cause().message} ${future.cause().javaClass.name}")
            if (retries++ < MAX_RETRIES && !closing) {
                workerGroup.schedule(
                    {
                        connect()
                    },
                    RETRY_INTERVAL,
                    TimeUnit.MILLISECONDS
                )
            } else {
                log.warn("Not retrying $target")
                val localAddress = future.channel().localAddress() as InetSocketAddress?
                for (listener in connectListeners) {
                    listener.onDisconnected(localAddress ?: InetSocketAddress("127.0.0.1", 999), target)
                }
            }
        } else {
            log.info("Connected to $target")
        }
    }

    companion object {
        init {
            InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
        }

        const val NUM_CLIENT_THREADS = 2
        const val MAX_RETRIES = 2
        const val RETRY_INTERVAL = 1000L
        private val log = contextLogger()
    }

    private class ConnectListenerEntry(
        val parent: TcpClient,
        val listener: TcpConnectListener
    ) : TcpConnectListener, AutoCloseable {
        override fun close() {
            parent.connectListeners.remove(this)
        }

        override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
            listener.onConnected(localAddress, remoteAddress)
        }

        override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
            listener.onDisconnected(localAddress, remoteAddress)
        }
    }

    private class MessageListenerEntry(
        val parent: TcpClient,
        val listener: TcpMessageListener
    ) : AutoCloseable, TcpMessageListener {
        override fun close() {
            parent.listeners.remove(this)
        }

        override fun onMessage(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress, msg: ByteArray) {
            listener.onMessage(localAddress, remoteAddress, msg)
        }
    }

    private class ClientChannelInitializer(val parent: TcpClient) : ChannelInitializer<SocketChannel>() {
        private val conf = parent.config

        override fun initChannel(ch: SocketChannel) {
            val pipeline = ch.pipeline()
            pipeline.addLast("frameEncoder", LengthFieldPrepender(4))
            pipeline.addLast("frameDecoder", LengthFieldBasedFrameDecoder(1024 * 1024, 0, 4, 0, 4))
            if (conf.trace) pipeline.addLast("logger", LoggingHandler(LogLevel.INFO))
            pipeline.addLast(
                TcpClientChannelHandler(
                    object : ChannelConnectionListener {
                        override fun onOpen(
                            channel: SocketChannel,
                            localAddress: InetSocketAddress,
                            remoteAddress: InetSocketAddress
                        ) {
                            parent.clientChannel = channel
                            while (parent.pendingSends.isNotEmpty()) {
                                val packet = parent.pendingSends.poll()
                                if (packet != null) {
                                    parent.sendData(packet)
                                }
                            }
                            for (listener in parent.connectListeners) {
                                listener.onConnected(localAddress, remoteAddress)
                            }
                        }

                        override fun onClose(
                            channel: SocketChannel,
                            localAddress: InetSocketAddress,
                            remoteAddress: InetSocketAddress
                        ) {
                            parent.clientChannel = null
                            for (listener in parent.connectListeners) {
                                listener.onDisconnected(localAddress, remoteAddress)
                            }
                        }
                    },
                    { localAddress, remoteAddress, msg ->
                        for (listener in parent.listeners) {
                            listener.onMessage(localAddress, remoteAddress, msg)
                        }
                    },
                    log
                )
            )
        }
    }

    fun registerConnectListener(listener: TcpConnectListener): AutoCloseable {
        val listenerEntry = ConnectListenerEntry(this, listener)
        connectListeners += listenerEntry
        return listenerEntry
    }

    fun registerMessageListener(listener: TcpMessageListener): AutoCloseable {
        val entry = MessageListenerEntry(this, listener)
        listeners += entry
        return entry
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
        val clientFuture = bootstrap.connect(target)
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
            }
            connectListeners.clear()
            listeners.clear()
        }
        log.info("Closed link to $target")
    }

    fun sendData(packet: ByteArray) {
        if (closing) {
            return
        }
        val channel = clientChannel
        if (channel != null) {
            val buf = channel.alloc().buffer(packet.size)
            buf.writeBytes(packet, 0, packet.size)
            clientChannel?.writeAndFlush(buf)
        } else {
            pendingSends += packet.copyOf()
        }
    }
}