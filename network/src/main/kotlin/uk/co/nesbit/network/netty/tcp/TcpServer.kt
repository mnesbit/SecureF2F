package uk.co.nesbit.network.netty.tcp

import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.LengthFieldBasedFrameDecoder
import io.netty.handler.codec.LengthFieldPrepender
import io.netty.handler.logging.LogLevel
import io.netty.handler.logging.LoggingHandler
import io.netty.util.concurrent.DefaultThreadFactory
import io.netty.util.internal.logging.InternalLoggerFactory
import io.netty.util.internal.logging.Slf4JLoggerFactory
import uk.co.nesbit.crypto.contextLogger
import uk.co.nesbit.network.api.LifeCycle
import uk.co.nesbit.network.netty.NettyServerEventLogger
import java.net.BindException
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class TcpServer(
    val bindAddress: InetSocketAddress,
    val config: TcpServerConfig
) : LifeCycle {
    private val lock = ReentrantLock()
    private var bossGroup: EventLoopGroup? = null
    private var workerGroup: EventLoopGroup? = null
    private var serverChannel: Channel? = null
    private val clientChannels = ConcurrentHashMap<InetSocketAddress, SocketChannel>()
    private val connectListeners = ConcurrentLinkedQueue<ConnectListenerEntry>()
    private val listeners = ConcurrentLinkedQueue<MessageListenerEntry>()

    companion object {
        init {
            InternalLoggerFactory.setDefaultFactory(Slf4JLoggerFactory.INSTANCE)
        }

        private val log = contextLogger()
    }

    private class ConnectListenerEntry(
        val parent: TcpServer,
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
        val parent: TcpServer,
        val listener: TcpMessageListener
    ) : AutoCloseable, TcpMessageListener {
        override fun close() {
            parent.listeners.remove(this)
        }

        override fun onMessage(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress, msg: ByteArray) {
            listener.onMessage(localAddress, remoteAddress, msg)
        }
    }

    private class ServerChannelInitializer(val parent: TcpServer) : ChannelInitializer<SocketChannel>() {
        private val conf = parent.config

        override fun initChannel(ch: SocketChannel) {
            val pipeline = ch.pipeline()
            pipeline.addLast()
            pipeline.addLast("frameEncoder", LengthFieldPrepender(4))
            pipeline.addLast("frameDecoder", LengthFieldBasedFrameDecoder(1024 * 1024, 0, 4, 0, 4))
            if (conf.trace) pipeline.addLast("logger", LoggingHandler(LogLevel.INFO))
            pipeline.addLast(
                TcpServerChannelHandler(
                    object : ChannelConnectionListener {
                        override fun onOpen(
                            channel: SocketChannel,
                            localAddress: InetSocketAddress,
                            remoteAddress: InetSocketAddress
                        ) {
                            parent.clientChannels[remoteAddress] = channel
                            for (listener in parent.connectListeners) {
                                listener.onConnected(localAddress, remoteAddress)
                            }
                        }

                        override fun onClose(
                            channel: SocketChannel,
                            localAddress: InetSocketAddress,
                            remoteAddress: InetSocketAddress
                        ) {
                            parent.clientChannels.remove(remoteAddress)
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

    fun sendData(packet: ByteArray, remoteAddress: InetSocketAddress) {
        val channel = clientChannels[remoteAddress]
        if (channel != null) {
            val buf = channel.alloc().buffer(packet.size)
            buf.writeBytes(packet, 0, packet.size)
            channel.writeAndFlush(buf)
        }
    }

    fun closeLink(remoteAddress: InetSocketAddress) {
        val channel = clientChannels[remoteAddress]
        if (channel != null) {
            channel.close()
            log.info("Closed $remoteAddress")
        } else {
            log.warn("Cannot find channel $remoteAddress to close")
        }
    }

    override fun start() {
        lock.withLock {
            bossGroup =
                NioEventLoopGroup(1, DefaultThreadFactory("TcpServer-$bindAddress-boss", Thread.MAX_PRIORITY))
            workerGroup = NioEventLoopGroup(
                4,
                DefaultThreadFactory("TcpServer-$bindAddress-worker", Thread.MAX_PRIORITY)
            )

            val server = ServerBootstrap()

            server.group(bossGroup, workerGroup).channel(NioServerSocketChannel::class.java)
                .option(ChannelOption.SO_BACKLOG, 100)
                .handler(NettyServerEventLogger(LogLevel.DEBUG))
                .childHandler(ServerChannelInitializer(this))

            log.info("Try to bind $bindAddress")
            val channelFuture = server.bind(bindAddress)
                .sync() // block/throw here as better to know we failed to claim port than carry on
            if (!channelFuture.isDone || !channelFuture.isSuccess) {
                throw BindException("Failed to bind port $bindAddress")
            }
            log.info("Listening on port $bindAddress")
            serverChannel = channelFuture.channel()

        }
    }

    override fun close() {
        lock.withLock {
            for (child in clientChannels.values) {
                child.close()
            }
            serverChannel?.close()
            serverChannel = null

            workerGroup?.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
            workerGroup?.terminationFuture()?.sync()
            workerGroup = null

            bossGroup?.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
            bossGroup?.terminationFuture()?.sync()
            bossGroup = null

            clientChannels.clear()

            listeners.clear()
            connectListeners.clear()
        }
    }

}