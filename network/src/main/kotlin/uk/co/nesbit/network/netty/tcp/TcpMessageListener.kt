package uk.co.nesbit.network.netty.tcp

import java.net.InetSocketAddress

fun interface TcpMessageListener {
    fun onMessage(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress, msg: ByteArray)
}