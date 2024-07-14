package uk.co.nesbit.network.netty.https

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import com.github.benmanes.caffeine.cache.RemovalCause
import com.github.benmanes.caffeine.cache.RemovalListener
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.handler.codec.http.HttpHeaderValues
import io.netty.util.concurrent.DefaultThreadFactory
import uk.co.nesbit.network.api.LifeCycle
import java.net.URI
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit

class HttpsClientManager(
    private val config: HttpsClientConfig
) : LifeCycle, RemovalListener<String, HttpsClient> {
    private var workerGroup: EventLoopGroup? = null
    private var sslDelegatedTaskExecutor: ExecutorService? = null
    private val clientCache: Cache<String, HttpsClient> = Caffeine.newBuilder()
        .maximumSize(10)
        .evictionListener(::onRemoval)
        .build()

    override fun onRemoval(key: String?, value: HttpsClient?, cause: RemovalCause?) {
        value?.close()
    }

    fun sendJSON(url: String, msg: String) {
        sendInternal(url, msg.toByteArray(Charsets.UTF_8), HttpHeaderValues.APPLICATION_JSON)
    }

    fun sendBytes(url: String, msg: ByteArray) {
        sendInternal(url, msg, HttpHeaderValues.APPLICATION_OCTET_STREAM)
    }

    private fun sendInternal(url: String, msg: ByteArray, contentType: CharSequence) {
        val parsedURL = URI(url).toURL()
        val cacheKey = "${parsedURL.host}|${parsedURL.port}"
        val httpClient = clientCache.get(cacheKey) { hostAndPort ->
            val parts = hostAndPort.split("|")
            val host = parts[0]
            var port = parts[1].toInt()
            if (port == -1) {
                port = 443
            }
            val client = HttpsClient(host, port, config, workerGroup!!, sslDelegatedTaskExecutor!!)
            client.registerClientListener(
                object : HttpsClientListener {
                    override fun onConnected(client: HttpsClient) {

                    }

                    override fun onDisconnected(client: HttpsClient) {
                        clientCache.invalidate(hostAndPort)
                    }

                }
            )
            client.start()
            client
        }
        httpClient.sendData(msg, parsedURL.path, contentType)
    }

    override fun start() {
        workerGroup = NioEventLoopGroup(
            HttpsClient.NUM_CLIENT_THREADS,
            DefaultThreadFactory("HttpsClientManager", Thread.MAX_PRIORITY)
        )
        sslDelegatedTaskExecutor = namedThreadPoolExecutor(maxPoolSize = 2, poolName = "HttpsClientManager-ssltask")
    }

    override fun close() {
        clientCache.invalidateAll()
        clientCache.cleanUp()

        workerGroup?.shutdownGracefully(100L, 200L, TimeUnit.MILLISECONDS)
        workerGroup?.terminationFuture()?.sync()
        workerGroup = null

        sslDelegatedTaskExecutor?.shutdown()
        sslDelegatedTaskExecutor = null
    }
}