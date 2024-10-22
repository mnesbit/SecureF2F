package uk.co.nesbit.crypto

import com.goterl.lazysodium.interfaces.DiffieHellman.SCALARMULT_CURVE25519_BYTES
import com.goterl.lazysodium.interfaces.DiffieHellman.SCALARMULT_CURVE25519_SCALARBYTES
import com.goterl.lazysodium.interfaces.Sign
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec
import uk.co.nesbit.utils.printHexBinary
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*
import kotlin.experimental.and
import kotlin.experimental.or

class NACLEd25519PublicKey(val keyBytes: ByteArray) : PublicKey {
    companion object {
        fun fromX509Encoded(x509EncodedBytes: ByteArray): NACLEd25519PublicKey {
            return NACLEd25519PublicKey(SubjectPublicKeyInfo.getInstance(x509EncodedBytes).publicKeyData.bytes)
        }
    }

    init {
        require(keyBytes.size == Sign.ED25519_PUBLICKEYBYTES) {
            "Ed25519 keys must be 32 bytes long"
        }
    }

    fun toBCPublicKey(): PublicKey {
        return ProviderCache.withKeyFactoryInstance<PublicKey>("Ed25519", "BC") {
            val x509KeySpec = X509EncodedKeySpec(encoded)
            generatePublic(x509KeySpec)
        }
    }

    override fun toString(): String = "PUBNACL25519:${keyBytes.printHexBinary()}"

    override fun getAlgorithm(): String = "NACLEd25519"

    override fun getEncoded(): ByteArray {
        val pubKeyInfo = SubjectPublicKeyInfo(AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), keyBytes)
        return pubKeyInfo.encoded
    }

    override fun getFormat(): String = "X.509"

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

fun BCEdDSAPublicKey.toNACLPublicKey(): PublicKey {
    return NACLEd25519PublicKey.fromX509Encoded(encoded)
}

class NACLEd25519PrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    init {
        require(keyBytes.size == Sign.ED25519_SEEDBYTES) {
            "Curve25519 keys must be 32 bytes long"
        }
    }

    override fun isDestroyed(): Boolean = false

    override fun destroy() {
        Arrays.fill(keyBytes, 0)
    }

    fun toBCPrivateKey(): PrivateKey {
        return ProviderCache.withKeyFactoryInstance<PrivateKey>("Ed25519", "BC") {
            val privKeyInfo =
                PrivateKeyInfo(AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), DEROctetString(keyBytes))
            val pkcs8KeySpec = PKCS8EncodedKeySpec(privKeyInfo.encoded)
            generatePrivate(pkcs8KeySpec)
        }
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

// Based upon https://github.com/str4d/ed25519-java/blob/master/src/net/i2p/crypto/eddsa/EdDSAPrivateKey.java
// OID 1.3.101.xxx
private const val OID_OLD = 100
private const val OID_ED25519 = 112
private const val OID_BYTE = 11
private const val IDLEN_BYTE = 6
private fun decodePKCS8(d: ByteArray): ByteArray {
    return try {
        //
        // Setup and OID check
        //
        var totlen = 48
        var idlen = 5
        val doid = d[OID_BYTE].toInt()
        if (doid == OID_OLD) {
            totlen = 49
            idlen = 8
        } else if (doid == OID_ED25519) {
            // Detect parameter value of NULL
            if (d[IDLEN_BYTE].toInt() == 7) {
                totlen = 50
                idlen = 7
            }
        } else {
            throw InvalidKeySpecException("unsupported key spec")
        }

        //
        // Pre-decoding check
        //
        if (d.size != totlen) {
            throw InvalidKeySpecException("invalid key spec length")
        }

        //
        // Decoding
        //
        var idx = 0
        if (d[idx++].toInt() != 0x30 || d[idx++].toInt() != totlen - 2 || d[idx++].toInt() != 0x02 || d[idx++].toInt() != 1 || d[idx++].toInt() != 0 || d[idx++].toInt() != 0x30 || d[idx++].toInt() != idlen || d[idx++].toInt() != 0x06 || d[idx++].toInt() != 3 || d[idx++].toInt() != 1 * 40 + 3 || d[idx++].toInt() != 101) {
            throw InvalidKeySpecException("unsupported key spec")
        }
        idx++ // OID, checked above
        // parameters only with old OID
        if (doid == OID_OLD) {
            if (d[idx++].toInt() != 0x0a || d[idx++].toInt() != 1 || d[idx++].toInt() != 1) {
                throw InvalidKeySpecException("unsupported key spec")
            }
        } else {
            // Handle parameter value of NULL
            //
            // Quoting RFC 8410 section 3:
            // > For all of the OIDs, the parameters MUST be absent.
            // >
            // > It is possible to find systems that require the parameters to be
            // > present. This can be due to either a defect in the original 1997
            // > syntax or a programming error where developers never got input where
            // > this was not true. The optimal solution is to fix these systems;
            // > where this is not possible, the problem needs to be restricted to
            // > that subsystem and not propagated to the Internet.
            //
            // Java's default keystore puts it in (when decoding as PKCS8 and then
            // re-encoding to pass on), so we must accept it.
            if (idlen == 7) {
                if (d[idx++].toInt() != 0x05 || d[idx++].toInt() != 0) {
                    throw InvalidKeySpecException("unsupported key spec")
                }
            }
            // PrivateKey wrapping the CurvePrivateKey
            if (d[idx++].toInt() != 0x04 || d[idx++].toInt() != 34) {
                throw InvalidKeySpecException("unsupported key spec")
            }
        }
        if (d[idx++].toInt() != 0x04 || d[idx++].toInt() != 32) {
            throw InvalidKeySpecException("unsupported key spec")
        }
        val rv = ByteArray(32)
        System.arraycopy(d, idx, rv, 0, 32)
        rv
    } catch (ioobe: IndexOutOfBoundsException) {
        throw InvalidKeySpecException(ioobe)
    }
}

fun BCEdDSAPrivateKey.toNACLPrivateKey(): PrivateKey {
    val key = this
    return ProviderCache.withKeyFactoryInstance<PrivateKey>("Ed25519", "BC") {
        val pkcs8KeySpec = getKeySpec(key, PKCS8EncodedKeySpec::class.java)
        NACLEd25519PrivateKey(decodePKCS8(pkcs8KeySpec.encoded))
    }

}


class NACLCurve25519PublicKey(val keyBytes: ByteArray) : PublicKey {
    init {
        require(keyBytes.size == SCALARMULT_CURVE25519_BYTES) {
            "Curve25519 keys must be 32 bytes long"
        }
    }

    override fun toString(): String = "PUBNACL25519:${keyBytes.printHexBinary()}"

    fun toBCPublicKey(): PublicKey {
        return ProviderCache.withKeyFactoryInstance<PublicKey>("X25519", "BC") {
            val pubKeyInfo = SubjectPublicKeyInfo(AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), keyBytes)
            val x509KeySpec = X509EncodedKeySpec(pubKeyInfo.encoded)
            generatePublic(x509KeySpec)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NACLCurve25519PublicKey

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }

    override fun getAlgorithm(): String = "NACLCurve25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}

fun BCXDHPublicKey.toNACLCurve25519PublicKey(): PublicKey {
    val key = this
    return ProviderCache.withKeyFactoryInstance<PublicKey>("X25519", "BC") {
        val rawKeySpec = getKeySpec(key, RawEncodedKeySpec::class.java)
        NACLCurve25519PublicKey(rawKeySpec.encoded)
    }
}

class NACLCurve25519PrivateKey(private val keyBytes: ByteArray) : PrivateKey {
    init {
        require(keyBytes.size == SCALARMULT_CURVE25519_SCALARBYTES) {
            "Curve25519 keys must be 32 bytes long"
        }
        // ensure it is a valid private key
        keyBytes[31] = keyBytes[31] and 0x7F
        keyBytes[31] = keyBytes[31] or 0x40
        keyBytes[0] = keyBytes[0] and 0xF8.toByte()
    }

    override fun toString(): String = "PRVNACL25519:${keyBytes.printHexBinary()}"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NACLCurve25519PrivateKey

        if (!org.bouncycastle.util.Arrays.constantTimeAreEqual(keyBytes, other.keyBytes)) return false

        return true
    }

    override fun hashCode(): Int {
        return Arrays.hashCode(keyBytes)
    }

    override fun getAlgorithm(): String = "NACLCurve25519"

    override fun getEncoded(): ByteArray = keyBytes

    override fun getFormat(): String = "RAW"
}
