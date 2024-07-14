package uk.co.nesbit.network

import com.fasterxml.jackson.databind.ObjectMapper
import io.netty.handler.codec.http.HttpHeaderValues
import io.netty.handler.codec.http.HttpMethod
import io.netty.handler.codec.http.HttpResponseStatus
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import uk.co.nesbit.crypto.X509
import uk.co.nesbit.crypto.generateECDSAKeyPair
import uk.co.nesbit.crypto.sign
import uk.co.nesbit.network.api.CertificateStore
import uk.co.nesbit.network.netty.https.*
import java.io.ByteArrayOutputStream
import java.io.OutputStreamWriter
import java.net.InetSocketAddress
import java.net.URI
import java.security.KeyStore
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal
import kotlin.math.abs
import kotlin.test.assertEquals
import kotlin.test.fail

class HttpsTests {
    private fun createTLSCerts(): Pair<KeyStore, KeyStore> {
        val caKeys = generateECDSAKeyPair()
        val trustStore = KeyStore.getInstance("pkcs12")
        trustStore.load(null)
        val keyStore = KeyStore.getInstance("pkcs12")
        keyStore.load(null)
        val now = Clock.systemUTC().instant()
        val signer = X509.getContentSigner(caKeys.public) { _, v ->
            caKeys.sign(v).toDigitalSignature()
        }
        val caSubject = X500Principal("CN=root, O=myroot, L=London, C=GB")
        val caCert = X509.createSelfSignedCACert(
            caSubject,
            caKeys.public,
            signer,
            Pair(now, now.plus(3650L, ChronoUnit.DAYS))
        )
        trustStore.setCertificateEntry("root", caCert)
        //keyStore.setKeyEntry("ca", caKeys.private, "caKeyPass".toCharArray(), arrayOf(caCert))

        val subject = X500Principal("CN=www.localhost.com, O=Test, L=London, C=GB")
        val tlsKeys = generateECDSAKeyPair()
        val tlsCert = X509.createCertificate(
            subject,
            tlsKeys.public,
            caSubject,
            caKeys.public,
            signer,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign),
            listOf(
                KeyPurposeId.id_kp_clientAuth,
                KeyPurposeId.id_kp_serverAuth
            ),
            true,
            Pair(now, now.plus(365L, ChronoUnit.DAYS)),
            altSubjectNames = listOf("127.0.0.1", "localhost")
        )
        keyStore.setKeyEntry("tls", tlsKeys.private, "keyPass".toCharArray(), arrayOf(tlsCert, caCert))
        return Pair(trustStore, keyStore)
    }

    private fun createClient(
        trustStore: KeyStore
    ): OkHttpClient {
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(trustStore)
        val trustManagers = trustManagerFactory.trustManagers.first() as X509TrustManager
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManagers), null)
        return OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustManagers)
            .build()
    }

    @Test
    fun `HTTPSServer ping test`() {
        val (truststore, keystore) = createTLSCerts()
        val conf = HttpsServerConfig(
            CertificateStore(keystore, "keyPass"),
            truststore
        )
        val httpsServer = HttpsServer("127.0.0.1", 8443, conf)
        httpsServer.registerMessageListener { _, _, _, _ ->
            fail("shouldn't receive any data")
        }
        val httpsClient = createClient(truststore)
        try {
            httpsServer.start()
            val getRequest = Request.Builder()
                .url("https://localhost:8443/ping")
                .get()
                .build()
            val getResponse = httpsClient.newCall(getRequest).execute()
            assertEquals(200, getResponse.code)
            val om = ObjectMapper()
            val time = om.readTree(getResponse.body!!.string()).get("time").textValue()
            assertEquals(true, abs(Instant.parse(time).epochSecond - Instant.now().epochSecond) < 60L)
            getResponse.close()
        } finally {
            httpsServer.close()
        }
    }

    @Test
    fun `HTTPSServer small inbox post test`() {
        val (truststore, keystore) = createTLSCerts()
        val conf = HttpsServerConfig(
            CertificateStore(keystore, "keyPass"),
            truststore
        )
        val testData = byteArrayOf(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09)
        val httpsServer = HttpsServer("127.0.0.1", 8443, conf)
        val httpsClient = createClient(truststore)
        var received = false
        httpsServer.registerMessageListener { _, target, uri, bytes ->
            assertArrayEquals(testData, bytes)
            assertEquals(URI.create("/inbox"), uri)
            assertEquals(InetSocketAddress("127.0.0.1", 8443), target)
            received = true
        }
        try {
            httpsServer.start()
            val postRequest = Request.Builder()
                .url("https://localhost:8443/inbox")
                .post(testData.toRequestBody("application/octet-stream".toMediaType()))
                .build()
            val postResponse = httpsClient.newCall(postRequest).execute()
            assertEquals(200, postResponse.code)
            assertEquals("", postResponse.body!!.string())
            postResponse.close()
            assertEquals(true, received)
        } finally {
            httpsServer.close()
        }
    }

    @Test
    fun `HTTPSServer small JSON post test`() {
        val (truststore, keystore) = createTLSCerts()
        val conf = HttpsServerConfig(
            CertificateStore(keystore, "keyPass"),
            truststore,
            uriMap = listOf(URIRouteEntry("/register", HttpMethod.POST, HttpHeaderValues.APPLICATION_JSON))
        )
        val testData = """{ "SomeData" : "Stuff and things", "b" : 1 }"""
        val httpsServer = HttpsServer("127.0.0.1", 8443, conf)
        val httpsClient = createClient(truststore)
        var received = false
        httpsServer.registerMessageListener { _, target, uri, bytes ->
            assertEquals(testData, String(bytes))
            assertEquals(URI.create("/register"), uri)
            assertEquals(InetSocketAddress("127.0.0.1", 8443), target)
            received = true
        }
        try {
            httpsServer.start()
            val postRequest = Request.Builder()
                .url("https://localhost:8443/register")
                .post(testData.toRequestBody("application/json".toMediaType()))
                .build()
            val postResponse = httpsClient.newCall(postRequest).execute()
            assertEquals(200, postResponse.code)
            assertEquals("", postResponse.body!!.string())
            postResponse.close()
            assertEquals(true, received)
        } finally {
            httpsServer.close()
        }
    }

    @Test
    fun `HTTPSServer bad requests test`() {
        val (truststore, keystore) = createTLSCerts()
        val conf = HttpsServerConfig(
            CertificateStore(keystore, "keyPass"),
            truststore,
            uriMap = listOf(
                URIRouteEntry("/register", HttpMethod.POST, HttpHeaderValues.APPLICATION_JSON),
                URIRouteEntry("/inbox", HttpMethod.POST, HttpHeaderValues.APPLICATION_OCTET_STREAM),
                URIRouteEntry("/ping", HttpMethod.GET, HttpHeaderValues.APPLICATION_JSON) { _: String ->
                    val message = """{ "time" : "${Instant.now()}" } """
                    createResponse(message.toByteArray(Charsets.UTF_8), HttpResponseStatus.OK)
                }
            )
        )
        val testData = """{ "SomeData" : "Stuff and things", "b" : 1 }"""
        val httpsServer = HttpsServer("127.0.0.1", 8443, conf)
        httpsServer.registerMessageListener { _, _, _, _ ->
            fail("No data should be received")
        }
        val httpsClient = createClient(truststore)
        try {
            httpsServer.start()
            val postRequest1 = Request.Builder()
                .url("https://localhost:8443/bad")
                .post(testData.toRequestBody("application/json".toMediaType()))
                .build()
            val postResponse1 = httpsClient.newCall(postRequest1).execute()
            assertEquals(404, postResponse1.code)
            postResponse1.close()
            val postRequest2 = Request.Builder()
                .url("https://localhost:8443/inbox")
                .post(testData.toRequestBody("application/json".toMediaType()))
                .build()
            val postResponse2 = httpsClient.newCall(postRequest2).execute()
            assertEquals(415, postResponse2.code)
            postResponse2.close()
            val postRequest3 = Request.Builder()
                .url("https://localhost:8443/register")
                .post(testData.toRequestBody("application/octet-stream".toMediaType()))
                .build()
            val postResponse3 = httpsClient.newCall(postRequest3).execute()
            assertEquals(415, postResponse3.code)
            postResponse3.close()
            val getRequest1 = Request.Builder()
                .url("https://localhost:8443/bad")
                .get()
                .build()
            val getResponse1 = httpsClient.newCall(getRequest1).execute()
            assertEquals(404, getResponse1.code)
            getResponse1.close()

        } finally {
            httpsServer.close()
        }
    }

    @Test
    fun `Chunked HTTPSServer post test`() {
        val (truststore, keystore) = createTLSCerts()
        val conf = HttpsServerConfig(
            CertificateStore(keystore, "keyPass"),
            truststore
        )
        val httpsServer = HttpsServer("127.0.0.1", 8443, conf)
        val httpsClient = createClient(truststore)
        var received = false
        httpsServer.registerMessageListener { _, target, uri, bytes ->
            val testBytes = ByteArrayOutputStream().use { baos ->
                OutputStreamWriter(baos, Charsets.UTF_8).use { sw ->
                    for (i in 0 until 5000) {
                        sw.write("Line $i\n")
                    }
                }
                baos.toByteArray()
            }

            assertArrayEquals(testBytes, bytes)
            assertEquals(URI.create("/inbox"), uri)
            assertEquals(InetSocketAddress("127.0.0.1", 8443), target)
            received = true
        }
        try {
            httpsServer.start()
            val streamingBody = object : RequestBody() {
                override fun contentType(): MediaType = "application/octet-stream".toMediaType()

                override fun writeTo(sink: BufferedSink) {
                    for (i in 0 until 5000) {
                        sink.writeUtf8("Line $i\n")
                    }
                }
            }
            val postRequest = Request.Builder()
                .url("https://localhost:8443/inbox")
                .post(streamingBody)
                .build()
            val postResponse = httpsClient.newCall(postRequest).execute()
            assertEquals(200, postResponse.code)
            assertEquals("", postResponse.body!!.string())
            postResponse.close()
            assertEquals(true, received)
        } finally {
            httpsServer.close()
        }
    }


    @Test
    fun `HTTPSClient no connect`() {
        val (truststore, _) = createTLSCerts()
        val clientConf = HttpsClientConfig(
            truststore
        )
        val httpsClient = HttpsClient("127.0.0.1", 8443, clientConf)
        var openCount = 0
        var closeCount = 0
        val disconnectLatch = CountDownLatch(1)
        httpsClient.registerClientListener(
            object : HttpsClientListener {
                override fun onConnected(client: HttpsClient) {
                    ++openCount
                }

                override fun onDisconnected(client: HttpsClient) {
                    disconnectLatch.countDown()
                    ++closeCount
                }
            }
        )
        try {
            httpsClient.start() // force a reconnect attempt
            assertEquals(true, disconnectLatch.await(10000L, TimeUnit.MILLISECONDS))
            assertEquals(1, closeCount)
            assertEquals(0, openCount)
        } finally {
            httpsClient.close()
            assertEquals(1, closeCount)
            assertEquals(0, openCount)
        }
    }

    @Test
    fun `HTTPSClient to HTTPSServer`() {
        val (truststore, keystore) = createTLSCerts()
        val serverConf = HttpsServerConfig(
            CertificateStore(keystore, "keyPass"),
            truststore,
            uriMap = listOf(
                URIRouteEntry("/register", HttpMethod.POST, HttpHeaderValues.APPLICATION_JSON),
                URIRouteEntry("/inbox", HttpMethod.POST, HttpHeaderValues.APPLICATION_OCTET_STREAM),
                URIRouteEntry("/ping", HttpMethod.GET, HttpHeaderValues.APPLICATION_JSON) { _: String ->
                    val message = """{ "time" : "${Instant.now()}" } """
                    createResponse(message.toByteArray(Charsets.UTF_8), HttpResponseStatus.OK)
                }
            )
        )
        val clientConf = HttpsClientConfig(
            truststore
        )
        val httpsServer = HttpsServer("127.0.0.1", 8443, serverConf)
        val httpsClient = HttpsClient("127.0.0.1", 8443, clientConf)
        var openCount = 0
        var closeCount = 0
        val connectLatch = CountDownLatch(1)
        val disconnectLatch = CountDownLatch(1)
        httpsClient.registerClientListener(
            object : HttpsClientListener {
                override fun onConnected(client: HttpsClient) {
                    connectLatch.countDown()
                    ++openCount
                }

                override fun onDisconnected(client: HttpsClient) {
                    disconnectLatch.countDown()
                    ++closeCount
                }
            }
        )
        var received = 0
        val receiveLatch = CountDownLatch(3)
        httpsServer.registerMessageListener { _, target, uri, bytes ->
            assertEquals("{ \"item\":\"$received\"}", String(bytes))
            assertEquals(URI.create("https://127.0.0.1:8443/register"), uri)
            assertEquals(InetSocketAddress("127.0.0.1", 8443), target)
            ++received
            receiveLatch.countDown()
        }
        try {
            httpsClient.start() // force a reconnect attempt
            httpsClient.sendData(
                "{ \"item\":\"0\"}".toByteArray(Charsets.UTF_8),
                "/register",
                HttpHeaderValues.APPLICATION_JSON
            )
            Thread.sleep(200L)
            httpsServer.start()
            assertEquals(true, connectLatch.await(10000L, TimeUnit.MILLISECONDS))
            assertEquals(0, closeCount)
            assertEquals(1, openCount)
            httpsClient.sendData(
                "{ \"item\":\"1\"}".toByteArray(Charsets.UTF_8),
                "/register",
                HttpHeaderValues.APPLICATION_JSON
            )
            httpsClient.sendData(
                "{ \"item\":\"2\"}".toByteArray(Charsets.UTF_8),
                "/register",
                HttpHeaderValues.APPLICATION_JSON
            )
            assertEquals(true, receiveLatch.await(10000L, TimeUnit.MILLISECONDS))
        } finally {
            httpsClient.close()
            httpsServer.close()
            assertEquals(1, closeCount)
            assertEquals(1, openCount)
            assertEquals(3, received)
        }
    }

}