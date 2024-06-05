package uk.co.nesbit.crypto.proxykeystore

import java.io.InputStream
import java.io.OutputStream
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.cert.Certificate
import java.util.*

internal class ProxyKeyStore : KeyStoreSpi() {
    private var proxyInfo: ProxyLoadParameters? = null

    private fun getCertificates(alias: String): Collection<Certificate>? = proxyInfo!!.certs[alias]

    override fun engineGetKey(alias: String, password: CharArray): Key? {
        val key = engineGetCertificate(alias)?.publicKey ?: return null
        return ProxyKey(key, proxyInfo!!.signer, key.algorithm)
    }

    override fun engineGetCertificate(alias: String): Certificate? =
        getCertificates(alias)?.firstOrNull()

    override fun engineGetCertificateChain(alias: String): Array<Certificate>? =
        getCertificates(alias)?.toTypedArray()

    override fun engineAliases(): Enumeration<String> =
        Collections.enumeration(proxyInfo!!.certs.keys)

    override fun engineContainsAlias(alias: String): Boolean = proxyInfo!!.certs.containsKey(alias)

    override fun engineSize() = proxyInfo!!.certs.size

    override fun engineIsKeyEntry(alias: String): Boolean = engineContainsAlias(alias)

    override fun engineLoad(param: KeyStore.LoadStoreParameter?) {
        if (param !is ProxyLoadParameters) throw IllegalArgumentException("ProxyKeyStore not initialised correctly")
        proxyInfo = param
    }

    override fun engineLoad(stream: InputStream, password: CharArray) {
        throw UnsupportedOperationException()
    }

    // Read only keystore, write operations are not supported.
    override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) {
        throw UnsupportedOperationException()
    }

    override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) {
        throw UnsupportedOperationException()
    }

    override fun engineDeleteEntry(alias: String?) {
        throw UnsupportedOperationException()
    }

    override fun engineIsCertificateEntry(alias: String?): Boolean {
        throw UnsupportedOperationException()
    }

    override fun engineGetCertificateAlias(cert: Certificate?): String? {
        throw UnsupportedOperationException()
    }

    override fun engineStore(stream: OutputStream?, password: CharArray?) {
        throw UnsupportedOperationException()
    }

    override fun engineGetCreationDate(alias: String) = throw UnsupportedOperationException()
}