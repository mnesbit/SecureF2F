package uk.co.nesbit.network.netty.https

import io.netty.channel.socket.SocketChannel

internal interface ChannelConnectionListener {
    fun onOpen(channel: SocketChannel)

    fun onClose(channel: SocketChannel)
}