package uk.co.nesbit.crypto.proxykeystore

import java.io.ByteArrayOutputStream
import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SignatureSpi

internal class ProxySignature(val algorithmName: String) : SignatureSpi() {
    private val data = ByteArrayOutputStream()
    private var proxy: ProxyKey? = null
    override fun engineInitVerify(publicKey: PublicKey) {
        throw UnsupportedOperationException()
    }

    override fun engineInitSign(privateKey: PrivateKey) {
        if (privateKey !is ProxyKey) throw InvalidKeyException("Key type not supported ${privateKey.javaClass.name}")
        proxy = privateKey
        data.reset()
    }

    override fun engineUpdate(b: Byte) {
        data.write(b.toInt())
    }

    override fun engineUpdate(b: ByteArray, off: Int, len: Int) {
        data.write(b, off, len)
    }

    override fun engineSign(): ByteArray {
        return proxy!!.run {
            signer(publicKey, algorithmName, data.toByteArray()).signature
        }
    }

    override fun engineVerify(sigBytes: ByteArray): Boolean {
        throw UnsupportedOperationException()
    }

    @Deprecated("Deprecated in Java")
    override fun engineSetParameter(param: String?, value: Any?) {
        throw UnsupportedOperationException()
    }

    @Deprecated("Deprecated in Java")
    override fun engineGetParameter(param: String?): Any {
        throw UnsupportedOperationException()
    }
}