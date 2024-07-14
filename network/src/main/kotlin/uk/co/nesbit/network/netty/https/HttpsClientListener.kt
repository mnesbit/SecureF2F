package uk.co.nesbit.network.netty.https

interface HttpsClientListener {
    fun onConnected(client: HttpsClient)
    fun onDisconnected(client: HttpsClient)
}