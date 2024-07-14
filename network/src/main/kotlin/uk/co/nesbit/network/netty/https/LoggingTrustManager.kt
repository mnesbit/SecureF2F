package uk.co.nesbit.network.netty.https

import org.bouncycastle.asn1.ASN1IA5String
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.X509CertificateHolder
import org.slf4j.LoggerFactory
import uk.co.nesbit.crypto.contextLogger
import uk.co.nesbit.crypto.debug
import uk.co.nesbit.utils.printHexBinary
import java.net.Socket
import java.net.URI
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager
import javax.security.auth.x500.X500Principal

internal const val DP_DEFAULT_ANSWER = "NO CRLDP ext"

internal val logger = LoggerFactory.getLogger("HttpsHelper")

/**
 * Returns all the CRL distribution points in the certificate as [URI]s along with the CRL issuer names, if any.
 */
internal fun X509Certificate.distributionPoints(): Map<URI, List<X500Principal>?> {
    logger.debug { "Checking CRLDPs for $subjectX500Principal" }

    val crldpExtBytes = getExtensionValue(Extension.cRLDistributionPoints.id)
    if (crldpExtBytes == null) {
        logger.debug(DP_DEFAULT_ANSWER)
        return emptyMap()
    }

    val derObjCrlDP = crldpExtBytes.toAsn1Object()
    val dosCrlDP = derObjCrlDP as? DEROctetString
    if (dosCrlDP == null) {
        logger.error("Expected to have DEROctetString, actual type: ${derObjCrlDP.javaClass}")
        return emptyMap()
    }
    val dpObj = dosCrlDP.octets.toAsn1Object()
    val crlDistPoint = CRLDistPoint.getInstance(dpObj)
    if (crlDistPoint == null) {
        logger.error("Could not instantiate CRLDistPoint, from: $dpObj")
        return emptyMap()
    }

    val dpMap = HashMap<URI, List<X500Principal>?>()
    for (distributionPoint in crlDistPoint.distributionPoints) {
        val distributionPointName = distributionPoint.distributionPoint
        if (distributionPointName?.type != DistributionPointName.FULL_NAME) continue
        val issuerNames = distributionPoint.crlIssuer?.names?.mapNotNull {
            if (it.tagNo == GeneralName.directoryName) {
                X500Principal(X500Name.getInstance(it.name).encoded)
            } else {
                null
            }
        }
        for (generalName in GeneralNames.getInstance(distributionPointName.name).names) {
            if (generalName.tagNo == GeneralName.uniformResourceIdentifier) {
                val uri = URI(ASN1IA5String.getInstance(generalName.name).string)
                dpMap[uri] = issuerNames
            }
        }
    }
    return dpMap
}

internal fun X509Certificate.distributionPointsToString(): String {
    return with(distributionPoints().keys) {
        if (isEmpty()) DP_DEFAULT_ANSWER else sorted().joinToString()
    }
}

internal fun ByteArray.toAsn1Object(): ASN1Primitive = ASN1InputStream(this).readObject()

internal fun X509Certificate.toSimpleString(): String {
    val bcCert = X509CertificateHolder(this.encoded)
    val keyIdentifier = try {
        SubjectKeyIdentifier.getInstance(bcCert.getExtension(Extension.subjectKeyIdentifier).parsedValue).keyIdentifier.printHexBinary()
    } catch (e: Exception) {
        "null"
    }
    val authorityKeyIdentifier = try {
        AuthorityKeyIdentifier.getInstance(bcCert.getExtension(Extension.authorityKeyIdentifier).parsedValue).keyIdentifier.printHexBinary()
    } catch (e: Exception) {
        "null"
    }
    val subject = bcCert.subject
    val issuer = bcCert.issuer
    return "$subject[$keyIdentifier] issued by $issuer[$authorityKeyIdentifier] $serialNumber [${distributionPointsToString()}]"
}

internal fun certPathToString(certPath: Array<out X509Certificate>?): String {
    if (certPath == null) {
        return "<empty certpath>"
    }
    return certPath.joinToString(System.lineSeparator()) { "  ${it.toSimpleString()}" }
}

internal class LoggingTrustManagerWrapper(private val wrapped: X509ExtendedTrustManager) : X509ExtendedTrustManager() {
    companion object {
        val log = contextLogger()
    }

    private fun certPathToStringFull(chain: Array<out X509Certificate>?): String {
        if (chain == null) {
            return "<empty certpath>"
        }
        return chain.joinToString(", ") { it.toString() }
    }

    private fun logErrors(chain: Array<out X509Certificate>?, block: () -> Unit) {
        try {
            block()
        } catch (ex: CertificateException) {
            log.error("Bad certificate path ${ex.message}:\r\n${certPathToStringFull(chain)}")
            throw ex
        }
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        log.debug { "Check Client Certpath:\r\n${certPathToString(chain)}" }
        logErrors(chain) { wrapped.checkClientTrusted(chain, authType, socket) }
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        log.debug { "Check Client Certpath:\r\n${certPathToString(chain)}" }
        logErrors(chain) { wrapped.checkClientTrusted(chain, authType, engine) }
    }

    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        log.debug { "Check Client Certpath:\r\n${certPathToString(chain)}" }
        logErrors(chain) { wrapped.checkClientTrusted(chain, authType) }
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) {
        log.debug { "Check Server Certpath:\r\n${certPathToString(chain)}" }
        logErrors(chain) { wrapped.checkServerTrusted(chain, authType, socket) }
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) {
        log.debug { "Check Server Certpath:\r\n${certPathToString(chain)}" }
        logErrors(chain) { wrapped.checkServerTrusted(chain, authType, engine) }
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        log.debug { "Check Server Certpath:\r\n${certPathToString(chain)}" }
        logErrors(chain) { wrapped.checkServerTrusted(chain, authType) }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = wrapped.acceptedIssuers

}
