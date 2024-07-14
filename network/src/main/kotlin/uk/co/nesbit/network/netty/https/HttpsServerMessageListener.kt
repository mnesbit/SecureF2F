package uk.co.nesbit.network.netty.https

import java.net.SocketAddress
import java.net.URI

fun interface HttpsServerMessageListener {
    fun onMessage(source: SocketAddress, target: SocketAddress, uri: URI, msg: ByteArray)
}