package uk.co.nesbit.crypto.proxykeystore

import uk.co.nesbit.crypto.DigitalSignature
import java.security.KeyStore
import java.security.PublicKey
import java.security.cert.X509Certificate

typealias SigningCallback = (key: PublicKey, algorithm: String, bytes: ByteArray) -> DigitalSignature

data class ProxyLoadParameters(
    val certs: Map<String, List<X509Certificate>>,
    val signer: SigningCallback
) : KeyStore.LoadStoreParameter {
    override fun getProtectionParameter(): KeyStore.ProtectionParameter {
        throw UnsupportedOperationException()
    }
}