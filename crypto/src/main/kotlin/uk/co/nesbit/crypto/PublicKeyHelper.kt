package uk.co.nesbit.crypto

import net.i2p.crypto.eddsa.EdDSAPublicKey
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec


object PublicKeyHelper {
    init {
        AvroTypeHelpers.registerHelper(PublicKey::class.java, { x -> x.toGenericRecord() }, { y -> PublicKeyHelper.fromGenericRecord(y) })
    }

    val publicKeySchema: Schema = Schema.Parser()
            .parse(PublicKeyHelper::class.java.getResourceAsStream("/uk/co/nesbit/crypto/publickey.avsc"))

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
                require(keyFormat == "X.509") { "Don't know how to deserialize" }
                EdDSAPublicKey(keySpec)
            }
            "EC", "RSA", "DH" -> {
                require(keyFormat == "X.509") { "Don't know how to deserialize" }
                val keyFactory = KeyFactory.getInstance(keyAlgorithm)
                keyFactory.generatePublic(keySpec)
            }
            "Curve25519" -> {
                require(keyFormat == "RAW") { "Don't know how to deserialize" }
                Curve25519PublicKey(publicKeyBytes)
            }
            else -> throw NotImplementedError("Unknown key algorithm $keyAlgorithm")
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
