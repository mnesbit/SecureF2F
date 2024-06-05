package uk.co.nesbit.crypto

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.sec.SECObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import java.io.*
import java.math.BigInteger
import java.net.InetAddress
import java.net.UnknownHostException
import java.security.PublicKey
import java.security.cert.*
import java.security.cert.Certificate
import java.time.Instant
import java.util.*
import javax.security.auth.x500.X500Principal
import kotlin.experimental.and
import kotlin.experimental.or


internal object X509Constants {
    const val CERTIFICATE_SERIAL_NUMBER_LENGTH = 16
    val ipAddressRegex =
        "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$".toRegex()
    val ipV6AddressRegex = "^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$".toRegex()
    val ipV6CompressedRegex =
        "^((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)::((?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?)$".toRegex()
    val dnsNameRegex =
        "^(\\*|[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]))*\$".toRegex()
}

object X509 {

    private fun generateCertificateSerialNumber(): BigInteger {
        val bytes = ByteArray(X509Constants.CERTIFICATE_SERIAL_NUMBER_LENGTH)
        newSecureRandom().nextBytes(bytes)
        // Set highest byte to 01xxxxxx to ensure positive sign and constant bit length.
        bytes[0] = bytes[0].and(0x3F).or(0x40)
        return BigInteger(bytes)
    }

    private fun addCrlInfo(builder: X509v3CertificateBuilder, crlDistPoint: String?, crlIssuer: X500Principal?) {
        if (crlDistPoint != null) {
            val distPointName =
                DistributionPointName(GeneralNames(GeneralName(GeneralName.uniformResourceIdentifier, crlDistPoint)))
            val crlIssuerGeneralNames = crlIssuer?.let {
                GeneralNames(GeneralName(X500Name(it.getName(X500Principal.RFC1779))))
            }
            // The second argument is flag that allows you to define what reason of certificate revocation is served by this distribution point see [ReasonFlags].
            // The idea is that you have different revocation per revocation reason. Since we won't go into such a granularity, we can skip that parameter.
            // The third argument allows you to specify the name of the CRL issuer, it needs to be consistent with the crl (IssuingDistributionPoint) extension and the idp argument.
            // If idp == true, set it, if idp == false, leave it null as done here.
            val distPoint = DistributionPoint(distPointName, null, crlIssuerGeneralNames)
            builder.addExtension(Extension.cRLDistributionPoints, false, CRLDistPoint(arrayOf(distPoint)))
        }
    }

    private val Certificate.x509: X509Certificate get() = requireNotNull(this as? X509Certificate) { "Not an X.509 certificate: $this" }

    fun getContentSigner(
        publicKey: PublicKey,
        signingService: (PublicKey, ByteArray) -> DigitalSignature
    ): ContentSigner {
        return object : ContentSigner {
            override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
                val keyInfo = SubjectPublicKeyInfo.getInstance(publicKey.encoded)
                return when (val keyAlgorithmId = keyInfo.algorithm.algorithm.id) {
                    "1.2.840.10045.2.1" -> AlgorithmIdentifier(
                        X9ObjectIdentifiers.ecdsa_with_SHA256,
                        SECObjectIdentifiers.secp256r1
                    )

                    "1.3.101.112" -> AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
                    "1.2.840.113549.1.1.1" -> AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, null)
                    else -> throw IllegalArgumentException("unknown algorithm type $keyAlgorithmId")
                }
            }

            private val byteStream = ByteArrayOutputStream()
            override fun getOutputStream(): OutputStream = byteStream

            override fun getSignature(): ByteArray {
                val signature = signingService(publicKey, byteStream.toByteArray())
                byteStream.reset()
                return signature.signature
            }

        }
    }

    fun createCertificate(
        subject: X500Principal,
        subjectPublicKey: PublicKey,
        issuer: X500Principal,
        issuerPublicKey: PublicKey,
        issuerSigner: ContentSigner,
        keyUsage: KeyUsage,
        purposes: List<KeyPurposeId>,
        isCA: Boolean,
        validityWindow: Pair<Instant, Instant>,
        crlDistPoint: String? = null,
        crlIssuer: X500Principal? = null,
        altSubjectNames: List<String> = emptyList()
    ): X509Certificate {
        val serial = generateCertificateSerialNumber()
        val keyPurposes = DERSequence(ASN1EncodableVector().apply { purposes.forEach { add(it) } })
        val windowStart = Date(validityWindow.first.toEpochMilli())
        val windowEnd = Date(validityWindow.second.toEpochMilli())
        var builder = JcaX509v3CertificateBuilder(
            issuer,
            serial,
            windowStart,
            windowEnd,
            subject,
            subjectPublicKey
        )
            .addExtension(
                Extension.subjectKeyIdentifier,
                false,
                JcaX509ExtensionUtils().createSubjectKeyIdentifier(subjectPublicKey)
            )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(isCA))
            .addExtension(Extension.keyUsage, true, keyUsage)
            .addExtension(Extension.extendedKeyUsage, false, keyPurposes)
            .addExtension(
                Extension.authorityKeyIdentifier,
                false,
                JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuerPublicKey)
            )

        if (altSubjectNames.isNotEmpty()) {
            val generalNames = altSubjectNames.map {
                if (X509Constants.ipAddressRegex.matches(it)
                    || X509Constants.ipV6AddressRegex.matches(it)
                    || X509Constants.ipV6CompressedRegex.matches(it)
                ) {
                    GeneralName(GeneralName.iPAddress, DEROctetString(InetAddress.getByName(it).address))
                } else if (X509Constants.dnsNameRegex.matches(it)) {
                    GeneralName(GeneralName.dNSName, it)
                } else throw java.lang.IllegalArgumentException("Unable to classify $it")
            }
            val subjectAltNames = GeneralNames.getInstance(DERSequence(generalNames.toTypedArray()))
            builder = builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames)
        }

        addCrlInfo(builder, crlDistPoint, crlIssuer)

        return builder.build(issuerSigner).run {
            val certificateFactory = CertificateFactory.getInstance("X.509")
            certificateFactory.generateCertificate(encoded.inputStream()).x509
        }
    }

    fun createSelfSignedCACert(
        issuer: X500Principal,
        issuerPublicKey: PublicKey,
        issuerSigner: ContentSigner,
        validityWindow: Pair<Instant, Instant>,
    ): X509Certificate {
        return createCertificate(
            issuer,
            issuerPublicKey,
            issuer,
            issuerPublicKey,
            issuerSigner,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign),
            purposes = emptyList(),
            isCA = true,
            validityWindow
        )
    }

    fun createCertificateSigningRequest(
        subject: X500Principal,
        publicKey: PublicKey,
        altSubjectNames: List<String>,
        contentSigner: ContentSigner
    ): PKCS10CertificationRequest {
        var basicRequest: PKCS10CertificationRequestBuilder = JcaPKCS10CertificationRequestBuilder(subject, publicKey)
        if (altSubjectNames.isNotEmpty()) {
            val extensions = ExtensionsGenerator()
            val generalNames = altSubjectNames.map {
                if (X509Constants.ipAddressRegex.matches(it)
                    || X509Constants.ipV6AddressRegex.matches(it)
                    || X509Constants.ipV6CompressedRegex.matches(it)
                ) {
                    GeneralName(GeneralName.iPAddress, DEROctetString(InetAddress.getByName(it).address))
                } else if (X509Constants.dnsNameRegex.matches(it)) {
                    GeneralName(GeneralName.dNSName, it)
                } else throw java.lang.IllegalArgumentException("Unable to classify $it")
            }
            val subjectAltNames = GeneralNames.getInstance(DERSequence(generalNames.toTypedArray()))
            extensions.addExtension(Extension.subjectAlternativeName, false, subjectAltNames)
            basicRequest =
                basicRequest.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions.generate())
        }

        return basicRequest.build(contentSigner)
    }

    fun certificateSigningRequestFromPEM(pem: String): PKCS10CertificationRequest {
        return StringReader(pem).use { sr ->
            val pemObject = PemReader(sr).readPemObject()
            PKCS10CertificationRequest(pemObject.content)
        }
    }

    fun certificateFromBytes(bytes: ByteArray): X509Certificate {
        val certificateFactory = CertificateFactory.getInstance("X.509")
        return ByteArrayInputStream(bytes).use {
            certificateFactory.generateCertificate(it).x509
        }
    }

    fun certificateFromPEM(pem: String): X509Certificate {
        return StringReader(pem).use { sr ->
            val pemObject = PemReader(sr).readPemObject()
            X509CertificateHolder(pemObject.content).run {
                val certificateFactory = CertificateFactory.getInstance("X.509")
                certificateFactory.generateCertificate(encoded.inputStream()).x509
            }
        }
    }

    fun certificatesFromPEM(pem: String): List<X509Certificate> {
        val certificates = mutableListOf<X509Certificate>()
        StringReader(pem).use { sr ->
            val reader = PemReader(sr)
            var pemObject = reader.readPemObject()
            while (pemObject != null) {
                X509CertificateHolder(pemObject.content).run {
                    val certificateFactory = CertificateFactory.getInstance("X.509")
                    certificates += certificateFactory.generateCertificate(encoded.inputStream()).x509
                }
                pemObject = reader.readPemObject()
            }
        }
        return certificates
    }

    fun validateCertificateChain(
        trustedRoots: Set<X509Certificate>,
        certificates: List<X509Certificate>,
        checkRevocation: Boolean = false,
        time: Instant? = null
    ) {
        require(certificates.isNotEmpty()) { "Certificate path must contain at least one certificate" }
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certPath = certificateFactory.generateCertPath(certificates)
        val trustAnchors = trustedRoots.map { TrustAnchor(it, null) }.toSet()
        val parameters = PKIXParameters(trustAnchors).apply {
            isRevocationEnabled = checkRevocation
            if (time != null) {
                date = Date.from(time)
            }
        }
        CertPathValidator.getInstance("PKIX").validate(certPath, parameters)
    }

    fun validateCertificateSigningRequest(csr: PKCS10CertificationRequest) {
        csr.isSignatureValid(JcaContentVerifierProviderBuilder().build(csr.subjectPublicKeyInfo))
    }
}

fun X509Certificate.toPEM(): String {
    ByteArrayOutputStream().use { baos ->
        OutputStreamWriter(baos).use { writer ->
            JcaPEMWriter(writer).use { pemWriter ->
                pemWriter.writeObject(this)
            }
        }
        return baos.toString(Charsets.UTF_8)
    }
}

fun PKCS10CertificationRequest.toPEM(): String {
    ByteArrayOutputStream().use { baos ->
        OutputStreamWriter(baos).use { writer ->
            JcaPEMWriter(writer).use { pemWriter ->
                val pemCSR = PemObject("CERTIFICATE REQUEST", this.encoded)
                pemWriter.writeObject(pemCSR)
            }
        }
        return baos.toString(Charsets.UTF_8)
    }
}

val PKCS10CertificationRequest.publicKey: PublicKey
    get() {
        val convertor = JcaPEMKeyConverter()
        return convertor.getPublicKey(this.subjectPublicKeyInfo)
    }

fun PKCS10CertificationRequest.getAltSubjectNames(): List<String> {
    val altSubjectNames = mutableListOf<String>()
    val csrExtensions = this.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)
    if (csrExtensions != null && csrExtensions.isNotEmpty()) {
        for (attribute in csrExtensions) {
            for (value in attribute.attributeValues) {
                val extensions = Extensions.getInstance(value)
                val gns: GeneralNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName)
                for (name in gns.getNames()) {
                    if (name.tagNo == GeneralName.rfc822Name) {
                        altSubjectNames += (name.name as DERIA5String).string
                    } else if (name.tagNo == GeneralName.dNSName) {
                        altSubjectNames += (name.name as DERIA5String).string
                    } else if (name.tagNo == GeneralName.iPAddress) {
                        try {
                            val addr = InetAddress.getByAddress((name.name as DEROctetString).getOctets())
                            altSubjectNames += addr.hostAddress
                        } catch (e: UnknownHostException) {
                            //ignore
                        }
                    }
                }
            }
        }
    }
    return altSubjectNames
}
