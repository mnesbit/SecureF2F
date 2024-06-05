package uk.co.nesbit.crypto

import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import uk.co.nesbit.crypto.proxykeystore.ProxyKeyStoreProvider
import uk.co.nesbit.crypto.proxykeystore.ProxyLoadParameters
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.time.Clock
import java.time.temporal.ChronoUnit
import java.util.*
import javax.security.auth.x500.X500Principal
import kotlin.test.assertEquals

class X509Test {
    @Test
    fun `test certificate creation`() {
        val keyPairs = listOf(
            generateRSAKeyPair(),
            generateECDSAKeyPair(),
            generateEdDSAKeyPair()
        )
        for (keyPair in keyPairs) {
            val signer = X509.getContentSigner(keyPair.public) { k, v ->
                assertEquals(keyPair.public, k)
                keyPair.sign(v).toDigitalSignature()
            }
            val now = Clock.systemUTC().instant()
            val issuerName = X500Principal("CN=me,O=Matthew,L=London,C=GB")
            val certificate = X509.createSelfSignedCACert(
                issuerName,
                keyPair.public,
                signer,
                Pair(now, now.plus(365L, ChronoUnit.DAYS))
            )
            val pem = certificate.toPEM()
            println(pem)
            val deserialized = X509.certificateFromPEM(pem)
            assertEquals(certificate, deserialized)
            certificate.checkValidity(Date(now.plusSeconds(5L).toEpochMilli()))
            certificate.verify(keyPair.public)
            X509.validateCertificateChain(setOf(certificate), listOf(certificate))
        }
    }

    @Test
    fun `CSR test`() {
        val keyPairs = listOf(
            generateRSAKeyPair(),
            generateECDSAKeyPair(),
            generateEdDSAKeyPair()
        )
        for (keyPair in keyPairs) {
            val signer = X509.getContentSigner(keyPair.public) { k, v ->
                assertEquals(keyPair.public, k)
                keyPair.sign(v).toDigitalSignature()
            }
            val csr = X509.createCertificateSigningRequest(
                X500Principal("CN=me,O=Matthew,L=London,C=GB"),
                keyPair.public,
                listOf("192.168.1.20", "::1", "www.myhost.com", "*.wibble.com"),
                signer
            )
            val pem = csr.toPEM()
            println(pem)
            val deserialized = X509.certificateSigningRequestFromPEM(pem)
            assertEquals(csr, deserialized)
            X509.validateCertificateSigningRequest(csr)
        }
    }

    @Test
    fun `simple cert chain`() {
        val rootKeys = generateECDSAKeyPair()
        val intermediateKeys = generateECDSAKeyPair()
        val tlsKeys = generateECDSAKeyPair()
        val now = Clock.systemUTC().instant()
        val issuerName = X500Principal("CN=root,O=ACME,L=London,C=GB")
        val rootSigner = X509.getContentSigner(rootKeys.public) { k, v ->
            assertEquals(rootKeys.public, k)
            rootKeys.sign(v).toDigitalSignature()
        }
        val rootCertificate = X509.createSelfSignedCACert(
            issuerName,
            rootKeys.public,
            rootSigner,
            Pair(now.minusSeconds(2L), now.plus(3650L, ChronoUnit.DAYS))
        )
        rootCertificate.checkValidity(Date.from(now))
        rootCertificate.verify(rootKeys.public)

        val intermediateName = X500Principal("CN=intermediate,OU=issuance,O=ACME,L=London,C=GB")
        val intermediateCert = X509.createCertificate(
            intermediateName,
            intermediateKeys.public,
            rootCertificate.subjectX500Principal,
            rootCertificate.publicKey,
            rootSigner,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign),
            purposes = listOf(
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_OCSPSigning,
                KeyPurposeId.id_kp_clientAuth
            ),
            isCA = true,
            Pair(now.minusSeconds(2L), now.plus(2L * 365L, ChronoUnit.DAYS)),
            crlDistPoint = "http://localhost:8080/crl/root.crl",
            crlIssuer = rootCertificate.subjectX500Principal
        )
        assertEquals(intermediateKeys.public, intermediateCert.publicKey)
        intermediateCert.checkValidity(Date.from(now))
        intermediateCert.verify(rootCertificate.publicKey)

        val intermediateSigner = X509.getContentSigner(intermediateCert.publicKey) { k, v ->
            assertEquals(intermediateKeys.public, k)
            intermediateKeys.sign(v).toDigitalSignature()
        }
        val tlsName = X500Principal("CN=localhost,O=nesbit,L=London,C=GB")
        val tlsCert = X509.createCertificate(
            tlsName,
            tlsKeys.public,
            intermediateCert.subjectX500Principal,
            intermediateCert.publicKey,
            intermediateSigner,
            KeyUsage(KeyUsage.digitalSignature),
            purposes = listOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth),
            isCA = false,
            Pair(now.minusSeconds(2L), now.plus(365L, ChronoUnit.DAYS)),
            crlDistPoint = "http://localhost:8080/crl/intermediate.crl",
            crlIssuer = intermediateCert.subjectX500Principal,
            altSubjectNames = listOf("127.0.0.1", "localhost", "www.nesbit.co.uk", "*.nesbit.co.uk")
        )
        tlsCert.checkValidity(Date.from(now))
        tlsCert.verify(intermediateCert.publicKey)
        val certChain = listOf(
            tlsCert,
            intermediateCert,
            rootCertificate
        )
        println(certChain)
        println(certChain.map { it.toPEM() })
        X509.validateCertificateChain(setOf(rootCertificate), certChain, false, now)
    }

    private fun genkeyByType(type: String): KeyPair {
        return when (type) {
            "ECDSA" -> generateECDSAKeyPair()
            "Ed25519" -> generateEdDSAKeyPair()
            "NACLEd25519" -> generateNACLKeyPair()
            "RSA" -> generateRSAKeyPair()
            else -> throw IllegalArgumentException("Not valid $type")
        }
    }

    @ParameterizedTest
    @CsvSource(
        "SHA256withECDSA,ECDSA",
        "SHA384withECDSA,ECDSA",
        "SHA512withECDSA,ECDSA",
        "SHA256withRSA,RSA",
        "SHA384withRSA,RSA",
        "SHA512withRSA,RSA",
        "Ed25519,Ed25519",
        "Ed25519,NACLEd25519",
        "SHA256withRSAandMGF1,RSA",
        "SHA384withRSAandMGF1,RSA",
        "SHA512withRSAandMGF1,RSA"
    )
    fun `proxied keystore`(algorithm: String, keyType: String) {
        ProxyKeyStoreProvider.install()
        val rootKeys = genkeyByType(keyType)
        assertEquals(
            rootKeys.public.algorithm,
            rootKeys.private.algorithm
        ) //proxy has to assume this for SSLEngine to find right keys
        val intermediateKeys = genkeyByType(keyType)
        val tlsKeys = genkeyByType(keyType)
        val now = Clock.systemUTC().instant()
        val issuerName = X500Principal("CN=root,O=ACME,L=London,C=GB")
        val rootSigner = X509.getContentSigner(rootKeys.public) { k, v ->
            assertEquals(rootKeys.public, k)
            rootKeys.sign(v).toDigitalSignature()
        }
        val rootCertificate = X509.createSelfSignedCACert(
            issuerName,
            rootKeys.public,
            rootSigner,
            Pair(now.minusSeconds(2L), now.plus(3650L, ChronoUnit.DAYS))
        )

        val intermediateName = X500Principal("CN=intermediate,OU=issuance,O=ACME,L=London,C=GB")
        val intermediateCert = X509.createCertificate(
            intermediateName,
            intermediateKeys.public,
            rootCertificate.subjectX500Principal,
            rootCertificate.publicKey,
            rootSigner,
            KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyCertSign or KeyUsage.cRLSign),
            purposes = listOf(
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_OCSPSigning,
                KeyPurposeId.id_kp_clientAuth
            ),
            isCA = true,
            Pair(now.minusSeconds(2L), now.plus(2L * 365L, ChronoUnit.DAYS)),
            crlDistPoint = "http://localhost:8080/crl/root.crl",
            crlIssuer = rootCertificate.subjectX500Principal
        )

        val intermediateSigner = X509.getContentSigner(intermediateCert.publicKey) { k, v ->
            assertArrayEquals(intermediateKeys.public.encoded, k.encoded)
            intermediateKeys.sign(v).toDigitalSignature()
        }
        val tlsName = X500Principal("CN=localhost,O=nesbit,L=London,C=GB")
        val tlsCert = X509.createCertificate(
            tlsName,
            tlsKeys.public,
            intermediateCert.subjectX500Principal,
            intermediateCert.publicKey,
            intermediateSigner,
            KeyUsage(KeyUsage.digitalSignature),
            purposes = listOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth),
            isCA = false,
            Pair(now.minusSeconds(2L), now.plus(365L, ChronoUnit.DAYS)),
            crlDistPoint = "http://localhost:8080/crl/intermediate.crl",
            crlIssuer = intermediateCert.subjectX500Principal,
            altSubjectNames = listOf("127.0.0.1", "localhost", "www.nesbit.co.uk", "*.nesbit.co.uk")
        )

        val certList = listOf(tlsCert, intermediateCert, rootCertificate)
        val proxyKeyStore = KeyStore.getInstance(ProxyKeyStoreProvider.ProviderKeystoreType)
        val params = ProxyLoadParameters(
            mapOf(
                "tls" to certList
            )
        ) { k, alg, v ->
            require(k == tlsKeys.public) {
                "invalid key"
            }
            tlsKeys.sign(v, alg).toDigitalSignature()
        }
        proxyKeyStore.load(params)
        assertEquals(true, proxyKeyStore.containsAlias("tls"))
        assertEquals(false, proxyKeyStore.containsAlias("x"))
        assertEquals(certList, proxyKeyStore.getCertificateChain("tls").toList())
        assertEquals(null, proxyKeyStore.getCertificateChain("x"))
        assertEquals(tlsCert, proxyKeyStore.getCertificate("tls"))
        assertEquals(null, proxyKeyStore.getCertificate("x"))
        val key = proxyKeyStore.getKey("tls", "dummy".toCharArray()) as PrivateKey
        val bytes = "hello".toByteArray()
        val sig = Signature.getInstance(algorithm)
        sig.initSign(key)
        sig.update(bytes)
        val signature = sig.sign()
        val digSig = DigitalSignature(sig.algorithm, signature)
        digSig.verify(tlsKeys.public, bytes)

        if (keyType != "NACLEd25519") { // can't sign direct with the NACL keys
            val notProxiedKey = genkeyByType(keyType)
            val sig2 = Signature.getInstance(algorithm)
            sig2.initSign(notProxiedKey.private)
            sig2.update(bytes)
            val signature2 = sig2.sign()
            val digSig2 = DigitalSignature(sig2.algorithm, signature2)
            digSig2.verify(notProxiedKey.public, bytes)
        }

        val proxyKeyStore3 = KeyStore.getInstance(ProxyKeyStoreProvider.ProviderKeystoreType)
        val params3 = ProxyLoadParameters(
            mapOf(
                "root" to listOf(rootCertificate)
            )
        ) { k, alg, v ->
            require(k == rootKeys.public) {
                "invalid key"
            }
            rootKeys.sign(v, alg).toDigitalSignature()
        }
        val bytes2 = "Bye Bye".toByteArray()
        proxyKeyStore3.load(params3)
        val key3 = proxyKeyStore3.getKey("root", "dummy".toCharArray()) as PrivateKey
        val sig3 = Signature.getInstance(algorithm)
        sig3.initSign(key3)
        sig3.update(bytes2)
        val signature3 = sig3.sign()
        val digSig3 = DigitalSignature(sig3.algorithm, signature3)
        digSig3.verify(rootKeys.public, bytes2)
    }
}