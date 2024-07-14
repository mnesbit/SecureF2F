package uk.co.nesbit.network.netty.https

import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.SocketChannel
import io.netty.handler.codec.http.*
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import io.netty.handler.ssl.SslHandshakeTimeoutException
import io.netty.handler.timeout.IdleStateEvent
import org.slf4j.Logger
import uk.co.nesbit.crypto.debug
import uk.co.nesbit.crypto.trace
import java.nio.channels.ClosedChannelException
import javax.net.ssl.SSLException

internal class HttpsClientChannelHandler(
    private val eventListener: ChannelConnectionListener,
    private val logger: Logger
) : SimpleChannelInboundHandler<HttpObject>() {
    override fun channelActive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        logger.debug { "New client connection ${ch.id()} from ${ch.localAddress()} to ${ch.remoteAddress()}" }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        val ch = ctx.channel()
        logger.debug { "Closed client connection ${ch.id()} from ${ch.localAddress()} to ${ch.remoteAddress()}" }
        eventListener.onClose(ch as SocketChannel)
        ctx.fireChannelInactive()
    }

    override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
        when (evt) {
            is SslHandshakeCompletionEvent -> {
                if (evt.isSuccess) {
                    val ch = ctx.channel()
                    logger.debug { "Handshake with ${ctx.channel().remoteAddress()} successful" }
                    eventListener.onOpen(ch as SocketChannel)
                } else {
                    val cause = evt.cause()
                    when {
                        cause is ClosedChannelException -> logger.warn("SSL handshake closed early")
                        cause is SslHandshakeTimeoutException -> logger.warn("SSL handshake timed out")
                        cause is SSLException && (cause.message?.contains("close_notify") == true) -> {
                            logger.warn("Received close_notify during handshake")
                        }

                        cause is SSLException && (cause.message?.contains("internal_error") == true) -> {
                            logger.warn("Received internal_error during handshake")
                        }

                        cause is SSLException && (cause.message?.contains("unrecognized_name") == true) -> {
                            logger.warn(
                                "Unrecognized server name error." +
                                        "This is most likely due to mismatch between the certificates subject alternative name and the host name."
                            )
                        }

                        cause is SSLException && (cause.message?.contains("Unrecognized server name indication") == true) -> {
                            logger.warn(
                                "Unrecognized server name error." +
                                        "This is most likely due to mismatch between the certificates subject alternative name and the host name."
                            )
                        }

                        else -> logger.warn("Handshake failure ${evt.cause().message}", evt.cause())
                    }
                    ctx.close()
                }
            }

            is IdleStateEvent -> {
                val ch = ctx.channel()
                logger.debug { "Closing connection with ${ch.remoteAddress()} due to inactivity" }
                ctx.close()
            }
        }
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

    override fun channelRead0(ctx: ChannelHandlerContext, msg: HttpObject) {
        if (msg is HttpResponse) {
            val responseCode = msg.status()
            if (responseCode != HttpResponseStatus.OK) {
                logger.warn(
                    "Received error HTTP response from ${ctx.channel().remoteAddress()}\n" +
                            "Protocol version: ${msg.protocolVersion()}\n" +
                            "Hostname: ${msg.headers()[HttpHeaderNames.HOST] ?: "unknown"}\n" +
                            "and the response code was $responseCode."
                )
                // if status error we eagerly close the connection in a blocking fashion so that we do not process anything more.
                ctx.close().get()
                return
            }
            logger.trace {
                "Received HTTP response from ${ctx.channel().remoteAddress()} " +
                        "Protocol version: ${msg.protocolVersion()} " +
                        "Hostname: ${msg.headers()[HttpHeaderNames.HOST] ?: "unknown"} " +
                        "Content length: ${msg.headers()[HttpHeaderNames.CONTENT_LENGTH]}"
            }
        }

        if (msg is LastHttpContent) { // any chunking should already be aggregated up
            val content = msg.content()
            if (logger.isTraceEnabled) {
                logger.trace("Read end of response body $msg content length ${content.readableBytes()}")
                if (content.isReadable) {
                    val sourceAddress = ctx.channel().remoteAddress()
                    val targetAddress = ctx.channel().localAddress()
                    val bytes = ByteArray(content.readableBytes())
                    content.readBytes(bytes)
                    logger.trace("received response data $sourceAddress $targetAddress ${String(bytes)}")
                }
            }
        }
    }
}