package uk.co.nesbit.network.netty.tcp

import io.netty.channel.socket.SocketChannel
import java.net.InetSocketAddress

internal interface ChannelConnectionListener {
    fun onOpen(channel: SocketChannel, localAddress: InetSocketAddress, remoteAddress: InetSocketAddress)

    fun onClose(channel: SocketChannel, localAddress: InetSocketAddress, remoteAddress: InetSocketAddress)
}