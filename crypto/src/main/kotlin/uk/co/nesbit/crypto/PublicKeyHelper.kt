package uk.co.nesbit.crypto

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.util.io.pem.PemReader
import uk.co.nesbit.avro.*
import java.io.ByteArrayOutputStream
import java.io.OutputStreamWriter
import java.io.StringReader
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.security.auth.DestroyFailedException

object PublicKeyHelper {
    init {
        AvroTypeHelpers.registerHelper(
            PublicKey::class.java,
            { x -> x.toGenericRecord() },
            { y -> fromGenericRecord(y) })
    }

    val publicKeySchema: Schema = Schema.Parser()
        .parse(javaClass.getResourceAsStream("/uk/co/nesbit/crypto/publickey.avsc"))

    // Primitive LRU cache to reduce expensive creation of EdDSA objects
    private const val MAX_CACHE = 20000L
    private val keyCache: Cache<ByteBuffer, PublicKey> = Caffeine.newBuilder().maximumSize(MAX_CACHE).build()

    fun deserialize(bytes: ByteArray): PublicKey {
        val keyRecord = publicKeySchema.deserialize(bytes)
        return fromGenericRecord(keyRecord)
    }

    fun fromGenericRecord(genericRecord: GenericRecord): PublicKey {
        val publicKeyBytes = genericRecord.getTyped<ByteArray>("publicKey")
        val keyAlgorithm = genericRecord.getTyped<String>("keyAlgorithm")
        val keyFormat = genericRecord.getTyped<String>("keyFormat")
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        return when (keyAlgorithm) {
            "Ed25519" -> {
                require(keyFormat == "X.509") { "Don't know how to deserialize" }
                val cacheKey = ByteBuffer.allocate(publicKeyBytes.size)
                cacheKey.put(publicKeyBytes)
                cacheKey.flip()
                val pk = keyCache.get(cacheKey) {
                    ProviderCache.withKeyFactoryInstance(keyAlgorithm, "BC") {
                        generatePublic(keySpec)
                    }
                }
                pk!!
            }
            "EC", "RSA" -> {
                require(keyFormat == "X.509") { "Don't know how to deserialize" }
                val cacheKey = ByteBuffer.allocate(publicKeyBytes.size)
                cacheKey.put(publicKeyBytes)
                cacheKey.flip()
                val pk = keyCache.get(cacheKey) {
                    ProviderCache.withKeyFactoryInstance(keyAlgorithm) {
                        generatePublic(keySpec)
                    }
                }
                pk!!
            }
            "DH" -> { // don't cache DH keys as they change a lot
                require(keyFormat == "X.509") { "Don't know how to deserialize" }
                ProviderCache.withKeyFactoryInstance(keyAlgorithm) {
                    generatePublic(keySpec)
                }
            }
            "Curve25519" -> {// don't cache DH keys as they change a lot
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                Curve25519PublicKey(publicKeyBytes)
            }
            "NACLEd25519" -> {
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                NACLEd25519PublicKey(publicKeyBytes)
            }
            "NACLCurve25519" -> {// don't cache DH keys as they change a lot
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                NACLCurve25519PublicKey(publicKeyBytes)
            }
            "ThresholdPublicKey" -> {
                require(keyFormat == "AVRO") { "Don't know how to deserialize" }
                ThresholdPublicKey.deserialize(publicKeyBytes)
            }
            else -> throw NotImplementedError("Unknown key algorithm $keyAlgorithm")
        }
    }

    fun fromPEM(pem: String): PublicKey {
        StringReader(pem).use { sr ->
            PemReader(sr).use { pemReader ->
                val content = pemReader.readPemObject().content
                val keySpec = X509EncodedKeySpec(content)
                val spkInfo = SubjectPublicKeyInfo.getInstance(content)
                val algId = spkInfo.algorithm.algorithm.id
                return when (algId) {
                    "1.3.101.112" -> {
                        ProviderCache.withKeyFactoryInstance("Ed25519", "BC") {
                            generatePublic(keySpec)
                        }
                    }
                    "1.2.840.10045.2.1" -> {
                        ProviderCache.withKeyFactoryInstance("EC") {
                            generatePublic(keySpec)
                        }
                    }
                    "1.2.840.113549.1.1.1" -> {
                        ProviderCache.withKeyFactoryInstance("RSA") {
                            generatePublic(keySpec)
                        }
                    }
                    "1.2.840.113549.1.3.1" -> {
                        ProviderCache.withKeyFactoryInstance("DH") {
                            generatePublic(keySpec)
                        }
                    }
                    "1.3.101.110" -> {
                        val bcKey = ProviderCache.withKeyFactoryInstance("X25519", "BC") {
                            generatePublic(keySpec)
                        }
                        (bcKey as BCXDHPublicKey).toCurve25519PublicKey()
                    }
                    else -> throw IllegalArgumentException("unknown algorithm OID $algId")
                }

            }
        }
    }
}

fun PublicKey.toGenericRecord(): GenericRecord {
    val keyRecord = GenericData.Record(PublicKeyHelper.publicKeySchema)
    keyRecord.putTyped("keyAlgorithm", this.algorithm)
    keyRecord.putTyped("keyFormat", this.format)
    keyRecord.putTyped("publicKey", this.encoded)
    return keyRecord
}

fun PublicKey.serialize() = this.toGenericRecord().serialize()

val PublicKey.id: SecureHash get() = SecureHash.secureHash(this.encoded)

fun PrivateKey.safeDestroy() {
    if (!isDestroyed && !javaClass.getMethod("destroy").isDefault) {
        try {
            destroy()
        } catch (ex: DestroyFailedException) {
            // not always implemented
        }
    }
}

fun PublicKey.toPEM(): String {
    ByteArrayOutputStream().use { baos ->
        OutputStreamWriter(baos).use { writer ->
            JcaPEMWriter(writer).use { pemWriter ->
                if (this.format == "X.509") {
                    pemWriter.writeObject(this)
                } else if (this is NACLEd25519PublicKey) {
                    pemWriter.writeObject(this.toBCPublicKey())
                } else if (this is Curve25519PublicKey) {
                    pemWriter.writeObject(this.toBCPublicKey())
                } else if (this is NACLCurve25519PublicKey) {
                    pemWriter.writeObject(this.toBCPublicKey())
                } else {
                    throw IllegalArgumentException("Unsupported key type $this")
                }
            }
        }
        return baos.toString(Charsets.UTF_8)
    }
}