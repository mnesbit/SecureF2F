package uk.co.nesbit.crypto.proxykeystore

import java.security.PrivateKey
import java.security.PublicKey

internal class ProxyKey(
    val publicKey: PublicKey,
    val signer: SigningCallback,
    private val alg: String
) : PrivateKey {
    companion object {
        const val ProxyKeyFormat = "PROXYKEY"
    }

    override fun getAlgorithm(): String = alg

    override fun getFormat(): String = ProxyKeyFormat

    override fun getEncoded(): ByteArray {
        throw NotImplementedError("Not implemented")
    }
}