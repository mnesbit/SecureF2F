package uk.co.nesbit.crypto

import com.goterl.lazycode.lazysodium.interfaces.Sign
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import uk.co.nesbit.utils.printHexBinary
import java.security.PrivateKey
import java.security.PublicKey

class NACLEd25519PublicKey(val keyBytes: ByteArray) : PublicKey {
    init {
        require(keyBytes.size == Sign.ED25519_PUBLICKEYBYTES) {
            "Ed25519 keys must be 32 bytes long"
        }
    }

    fun toI2PPublicKey(): PublicKey {
        return EdDSAPublicKey(EdDSAPublicKeySpec(keyBytes, EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
    }

    fun toTinkPublicKey(): PublicKey {
        return TinkEd25519PublicKey(keyBytes)
    }

    override fun toString(): String = "PUBNACL25519:${keyBytes.printHexBinary()}"

    override fun getAlgorithm(): String = "NACLEd25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NACLEd25519PublicKey

        if (!keyBytes.contentEquals(other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return keyBytes.contentHashCode()
    }
}

fun EdDSAPublicKey.toNACLPublicKey(): PublicKey {
    return NACLEd25519PublicKey(this.abyte)
}

class NACLEd25519PrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    init {
        require(keyBytes.size == Sign.ED25519_SEEDBYTES) {
            "Curve25519 keys must be 32 bytes long"
        }
    }

    fun toI2PPrivateKey(): PrivateKey {
        return EdDSAPrivateKey(EdDSAPrivateKeySpec(keyBytes, EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
    }

    fun toTinkPrivateKey(): PrivateKey {
        return TinkEd25519PrivateKey(keyBytes)
    }

    override fun toString(): String = "PRVNACL25519:${keyBytes.printHexBinary()}"

    override fun getAlgorithm(): String = "NACLEd25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NACLEd25519PrivateKey

        if (!keyBytes.contentEquals(other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return keyBytes.contentHashCode()
    }
}

fun EdDSAPrivateKey.toNACLPrivateKey(): PrivateKey {
    return NACLEd25519PrivateKey(this.seed)
}
