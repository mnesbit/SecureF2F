package uk.co.nesbit.network.netty.https

import java.security.KeyStore
import java.time.Duration

data class HttpsClientConfig(
    val trustStore: KeyStore,
    val sslHandshakeTimeout: Duration = DEFAULT_SSL_HANDSHAKE_TIMEOUT,
    val trace: Boolean = false
)