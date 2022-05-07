package uk.co.nesbit.crypto

import djb.Curve25519
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec
import uk.co.nesbit.utils.printHexBinary
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.*

class Curve25519PublicKey(val keyBytes: ByteArray) : PublicKey {
    init {
        require(keyBytes.size == Curve25519.KEY_SIZE) {
            "Curve25519 keys must be 32 bytes long"
        }
    }

    override fun toString(): String = "PUB25519:${keyBytes.printHexBinary()}"

    fun toBCPublicKey(): PublicKey {
        return ProviderCache.withKeyFactoryInstance<PublicKey>("X25519", "BC") {
            val pubKeyInfo = SubjectPublicKeyInfo(AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), keyBytes)
            val x509KeySpec = X509EncodedKeySpec(pubKeyInfo.encoded)
            generatePublic(x509KeySpec)
        }
    }

    fun toNACLCurve25519PublicKey(): PublicKey = NACLCurve25519PublicKey(keyBytes)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Curve25519PublicKey

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }

    override fun getAlgorithm(): String = "Curve25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}

fun BCXDHPublicKey.toCurve25519PublicKey(): PublicKey {
    val key = this
    return ProviderCache.withKeyFactoryInstance<PublicKey>("X25519", "BC") {
        val rawKeySpec = getKeySpec(key, RawEncodedKeySpec::class.java)
        Curve25519PublicKey(rawKeySpec.encoded)
    }
}

class Curve25519PrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    init {
        require(keyBytes.size == Curve25519.KEY_SIZE) {
            "Curve25519 keys must be 32 bytes long"
        }
        Curve25519.clamp(keyBytes) // ensure it is a valid private key
    }

    override fun isDestroyed(): Boolean = false

    override fun destroy() {
        Arrays.fill(keyBytes, 0)
    }

    override fun toString(): String = "PRV25519:${keyBytes.printHexBinary()}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as Curve25519PrivateKey

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }

    override fun getAlgorithm(): String = "Curve25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}
