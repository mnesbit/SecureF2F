package uk.co.nesbit

import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import uk.co.nesbit.crypto.X509
import uk.co.nesbit.crypto.generateECDSAKeyPair
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.sign
import uk.co.nesbit.network.api.*
import uk.co.nesbit.network.mocknet.DnsMockActor
import uk.co.nesbit.network.treeEngine.TreeNode
import uk.co.nesbit.simpleactor.ActorSystem
import java.security.KeyStore
import java.time.Clock
import java.time.temporal.ChronoUnit
import javax.security.auth.x500.X500Principal

object TransportBuilder {
    fun createNetwork(
        mode: TransportMode,
        actorSystem: ActorSystem,
        simNetwork: Map<Address, Set<Address>>
    ): List<TreeNode> {
        return when (mode) {
            TransportMode.Memory -> createMockNetwork(actorSystem, simNetwork)
            TransportMode.TCP -> createTCPNetwork(actorSystem, simNetwork)
            TransportMode.HTTPS -> createHTTPSNetwork(actorSystem, simNetwork)
        }
    }

    private fun createMockNetwork(actorSystem: ActorSystem, simNetwork: Map<Address, Set<Address>>): List<TreeNode> {
        val simNodes = mutableListOf<TreeNode>()
        actorSystem.actorOf(DnsMockActor.getProps(), "Dns")
        for (networkAddress in simNetwork.keys) {
            val links = simNetwork[networkAddress]!!
            val config = NetworkConfiguration(networkAddress, networkAddress, false, links, emptySet())
            simNodes += TreeNode(actorSystem, config)
        }
        return simNodes
    }

    private fun createTCPNetwork(actorSystem: ActorSystem, simNetwork: Map<Address, Set<Address>>): List<TreeNode> {
        val simNodes = mutableListOf<TreeNode>()
        for (networkAddress in simNetwork.keys) {
            val tcpAddress: Address = (networkAddress as NetworkAddress).toLocalPublicAddress()
            val links = simNetwork[networkAddress]!!
            val tcpLinks: Set<Address> = links.map { (it as NetworkAddress).toLocalPublicAddress() }.toSet()
            val config = NetworkConfiguration(tcpAddress, tcpAddress, false, tcpLinks, emptySet())
            simNodes += TreeNode(actorSystem, config)
        }
        return simNodes
    }

    private fun createHTTPSNetwork(actorSystem: ActorSystem, simNetwork: Map<Address, Set<Address>>): List<TreeNode> {
        val secureRand = newSecureRandom()
        val rootKeys = generateECDSAKeyPair(secureRand)
        val now = Clock.systemUTC().instant()
        val issuerName = X500Principal("CN=Test Root,O=ACME,L=London,C=GB")
        val rootSigner = X509.getContentSigner(rootKeys.public) { k, v ->
            rootKeys.sign(v).toDigitalSignature()
        }
        val trustRootCert = X509.createSelfSignedCACert(
            issuerName,
            rootKeys.public,
            rootSigner,
            Pair(now, now.plus(3650L, ChronoUnit.DAYS))
        )
        val trustStore = KeyStore.getInstance("PKCS12")
        trustStore.load(null)
        trustStore.setCertificateEntry("root", trustRootCert)
        val simNodes = mutableListOf<TreeNode>()
        for (networkAddress in simNetwork.keys) {
            val httpsAddress: URLAddress = (networkAddress as NetworkAddress).toLocalHTTPSAddress()
            val nodeHTTPSKeys = generateECDSAKeyPair(secureRand)
            val nodeKeyStore = KeyStore.getInstance("PKCS12")
            nodeKeyStore.load(null)
            val subject = X500Principal("CN=${httpsAddress.url}, O=node_${networkAddress.id},C=GB")
            val nodeHTTPSCert = X509.createCertificate(
                subject,
                nodeHTTPSKeys.public,
                issuerName,
                rootKeys.public,
                rootSigner,
                KeyUsage(KeyUsage.digitalSignature),
                purposes = listOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth),
                isCA = false,
                Pair(now.minusSeconds(2L), now.plus(365L, ChronoUnit.DAYS)),
                crlDistPoint = "http://localhost:8080/crl/intermediate.crl",
                crlIssuer = trustRootCert.subjectX500Principal,
                altSubjectNames = listOf("127.0.0.1", "localhost")
            )
            val keyPassword = "password"
            nodeKeyStore.setKeyEntry(
                "https_key",
                nodeHTTPSKeys.private,
                keyPassword.toCharArray(),
                arrayOf(nodeHTTPSCert, trustRootCert)
            )
            val links = simNetwork[networkAddress]!!
            val httpsLinks: Set<Address> = links.map { (it as NetworkAddress).toLocalHTTPSAddress() }.toSet()
            val config = NetworkConfiguration(
                httpsAddress,
                httpsAddress,
                false,
                httpsLinks,
                emptySet(),
                trustStore,
                CertificateStore(
                    nodeKeyStore,
                    keyPassword
                )
            )
            simNodes += TreeNode(actorSystem, config)

        }
        return simNodes
    }
}