package uk.co.nesbit.network.netty.https

import io.netty.handler.codec.http.HttpHeaderValues
import io.netty.handler.codec.http.HttpMethod
import io.netty.handler.codec.http.HttpResponse
import io.netty.handler.codec.http.HttpResponseStatus
import uk.co.nesbit.network.api.CertificateStore
import java.security.KeyStore
import java.time.Duration
import java.time.Instant

// Set at least 3 times higher than sun.security.provider.certpath.URICertStore.DEFAULT_CRL_CONNECT_TIMEOUT which is 15 sec
val DEFAULT_SSL_HANDSHAKE_TIMEOUT: Duration = Duration.ofSeconds(60L)

fun interface ResponseFactory {
    fun generateResponse(path: String): HttpResponse
}

data class URIRouteEntry(
    val path: String,
    val method: HttpMethod,
    val contentType: CharSequence,
    val responseFactory: ResponseFactory? = null
)

data class HttpsServerConfig(
    val keyStore: CertificateStore,
    val trustStore: KeyStore,
    val uriMap: List<URIRouteEntry> = listOf(
        URIRouteEntry("/register", HttpMethod.POST, HttpHeaderValues.APPLICATION_OCTET_STREAM),
        URIRouteEntry("/unregister", HttpMethod.POST, HttpHeaderValues.APPLICATION_OCTET_STREAM),
        URIRouteEntry("/inbox", HttpMethod.POST, HttpHeaderValues.APPLICATION_OCTET_STREAM),
        URIRouteEntry("/ping", HttpMethod.GET, HttpHeaderValues.APPLICATION_JSON) { _: String ->
            val message = """{ "time" : "${Instant.now()}" } """
            createResponse(message.toByteArray(Charsets.UTF_8), HttpResponseStatus.OK)
        }
    ),
    val sslHandshakeTimeout: Duration = DEFAULT_SSL_HANDSHAKE_TIMEOUT,
    val trace: Boolean = false
)