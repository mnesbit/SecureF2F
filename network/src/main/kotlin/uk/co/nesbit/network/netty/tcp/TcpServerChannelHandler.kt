package uk.co.nesbit.network.netty.tcp

import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.socket.SocketChannel
import io.netty.util.ReferenceCountUtil
import org.slf4j.Logger
import java.net.InetSocketAddress

internal class TcpServerChannelHandler(
    private val eventListener: ChannelConnectionListener,
    private val messageListener: TcpMessageListener,
    private val logger: Logger
) : ChannelInboundHandlerAdapter() {
    private lateinit var remoteAddress: InetSocketAddress

    override fun channelActive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        remoteAddress = ch.remoteAddress() as InetSocketAddress
        val localAddress = ch.localAddress() as InetSocketAddress
        logger.info("New client connection ${ch.id()} from $localAddress to $remoteAddress")
        eventListener.onOpen(ch as SocketChannel, localAddress, remoteAddress)
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        val localAddress = ch.localAddress() as InetSocketAddress
        logger.info("Closed client connection ${ch.id()} from $localAddress to $remoteAddress")
        eventListener.onClose(ch as SocketChannel, localAddress, remoteAddress)
        ctx.fireChannelInactive()
    }

    override fun channelReadComplete(ctx: ChannelHandlerContext) {
        // Nothing more to read from the transport in this event-loop run. Simply flush
        ctx.flush()
    }

    @Deprecated("Deprecated but still needed")
    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        val message = cause.message ?: ""
        logger.warn("Closing channel due to unrecoverable exception $message", cause)
        ctx.close()
    }

    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
        try {
            if (msg is ByteBuf) {
                val packet = ByteArray(msg.readableBytes())
                msg.readBytes(packet)
                val localAddress = ctx.channel().localAddress() as InetSocketAddress
                messageListener.onMessage(localAddress, remoteAddress, packet)
            }
        } finally {
            ReferenceCountUtil.release(msg)
        }
    }
}