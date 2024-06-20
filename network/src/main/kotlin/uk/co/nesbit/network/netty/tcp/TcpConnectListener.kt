package uk.co.nesbit.network.netty.tcp

import java.net.InetSocketAddress

interface TcpConnectListener {
    fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress)
    fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress)
}