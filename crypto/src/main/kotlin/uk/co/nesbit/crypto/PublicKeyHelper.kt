package uk.co.nesbit.crypto

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import java.nio.ByteBuffer
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec


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
            "EdDSA" -> {
                require(keyFormat == "RAW" || keyFormat == "X.509") { "Don't know how to deserialize" }
                val cacheKey = ByteBuffer.allocate(publicKeyBytes.size)
                cacheKey.put(publicKeyBytes)
                cacheKey.flip()
                val pk = keyCache.get(cacheKey) {
                    if (keyFormat == "RAW") {
                        EdDSAPublicKey(EdDSAPublicKeySpec(publicKeyBytes, EdDSANamedCurveTable.ED_25519_CURVE_SPEC))
                    } else {
                        EdDSAPublicKey(keySpec)
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
            "TinkEd25519" -> {
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                TinkEd25519PublicKey(publicKeyBytes)
            }
            "NACLEd25519" -> {
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                NACLEd25519PublicKey(publicKeyBytes)
            }
            "NACLCurve25519" -> {// don't cache DH keys as they change a lot
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                NACLCurve25519PublicKey(publicKeyBytes)
            }
            else -> throw NotImplementedError("Unknown key algorithm $keyAlgorithm")
        }
    }
}

fun PublicKey.toGenericRecord(): GenericRecord {
    val keyRecord = GenericData.Record(PublicKeyHelper.publicKeySchema)
    keyRecord.putTyped("keyAlgorithm", this.algorithm)
    if (this is EdDSAPublicKey) { // Shorten the EdDSA back to 32 bytes
        keyRecord.putTyped("keyFormat", "RAW")
        keyRecord.putTyped("publicKey", this.abyte)
    } else {
        keyRecord.putTyped("keyFormat", this.format)
        keyRecord.putTyped("publicKey", this.encoded)
    }
    return keyRecord
}

fun PublicKey.serialize() = this.toGenericRecord().serialize()

val PublicKey.id: SecureHash get() = SecureHash.secureHash(this.encoded)
