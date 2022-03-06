package uk.co.nesbit.crypto

import com.google.crypto.tink.subtle.Ed25519Sign
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import uk.co.nesbit.utils.printHexBinary
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*

class TinkEd25519PublicKey(val keyBytes: ByteArray) : PublicKey {
    init {
        require(keyBytes.size == Ed25519Sign.SECRET_KEY_LEN) {
            "Ed25519 keys must be 32 bytes long"
        }
    }

    fun toI2PPublicKey(): PublicKey {
        return EdDSAPublicKey(EdDSAPublicKeySpec(keyBytes, EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
    }

    fun toNACLPublicKey(): PublicKey {
        return NACLEd25519PublicKey(keyBytes)
    }

    override fun toString(): String = "PUBTINK25519:${keyBytes.printHexBinary()}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TinkEd25519PublicKey

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }

    override fun getAlgorithm(): String = "TinkEd25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}

fun EdDSAPublicKey.toTinkPublicKey(): PublicKey {
    return TinkEd25519PublicKey(this.abyte)
}

class TinkEd25519PrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    init {
        require(keyBytes.size == Ed25519Sign.SECRET_KEY_LEN) {
            "Curve25519 keys must be 32 bytes long"
        }
    }

    override fun isDestroyed(): Boolean = false

    override fun destroy() {
        Arrays.fill(keyBytes, 0)
    }

    fun toI2PPrivateKey(): PrivateKey {
        return EdDSAPrivateKey(EdDSAPrivateKeySpec(keyBytes, EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
    }

    fun toNACLPrivateKey(): PrivateKey {
        return NACLEd25519PrivateKey(keyBytes)
    }

    override fun toString(): String = "PRVTINK25519:${keyBytes.printHexBinary()}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TinkEd25519PrivateKey

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }

    override fun getAlgorithm(): String = "TinkEd25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}

fun EdDSAPrivateKey.toTinkPrivateKey(): PrivateKey {
    return TinkEd25519PrivateKey(this.seed)
}

