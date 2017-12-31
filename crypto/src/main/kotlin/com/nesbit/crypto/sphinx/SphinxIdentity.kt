package com.nesbit.crypto.sphinx

import com.nesbit.avro.*
import com.nesbit.crypto.*
import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom

class SphinxPublicIdentity(val signingPublicKey: PublicKey,
                           val diffieHellmanPublicKey: PublicKey,
                           val hashChain: HashChainPublic,
                           val publicAddress: String?) : AvroConvertible {
    constructor(signatureRecord: GenericRecord) :
            this(signatureRecord.getTyped("signingPublicKey"),
                    signatureRecord.getTyped("diffieHellmanPublicKey"),
                    signatureRecord.getTyped("hashChain", ::HashChainPublic),
                    signatureRecord.getTyped<String?>("publicAddress"))

    companion object {
        val ID_HASH_ALGORITHM = "SHA-256"
        val sphinxIdentitySchema = Schema.Parser().
                addTypes(mapOf(PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema,
                        HashChainPublic.hashChainSchema.fullName to HashChainPublic.hashChainSchema)).
                parse(DigitalSignature::class.java.getResourceAsStream("/com/nesbit/crypto/sphinx/sphinxidentity.avsc"))

        fun deserialize(bytes: ByteArray): SphinxPublicIdentity {
            val idRecord = sphinxIdentitySchema.deserialize(bytes)
            return SphinxPublicIdentity(idRecord)
        }

    }

    init {
        require(diffieHellmanPublicKey.algorithm == "Curve25519")
    }

    override fun toGenericRecord(): GenericRecord {
        val hashChainRecord = GenericData.Record(sphinxIdentitySchema)
        hashChainRecord.putTyped("signingPublicKey", signingPublicKey)
        hashChainRecord.putTyped("diffieHellmanPublicKey", diffieHellmanPublicKey)
        hashChainRecord.putTyped("hashChain", hashChain)
        hashChainRecord.putTyped("publicAddress", publicAddress)
        return hashChainRecord
    }

    val id: SecureHash by lazy {
        val bytes = this.serialize()
        bytes.secureHash(ID_HASH_ALGORITHM)
    }

    fun verifyChainValue(hashBytes: ByteArray, stepsFromEnd: Int): Boolean = hashChain.verifyChainValue(hashBytes, stepsFromEnd)

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int): Boolean = hashChain.verifyChainValue(hash, stepsFromEnd)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SphinxPublicIdentity

        if (id != other.id) return false

        return true
    }

    override fun hashCode(): Int {
        return id.hashCode()
    }
}

class SphinxIdentityKeyPair(val signingKeys: KeyPair, val diffieHellmanKeys: KeyPair, val hashChain: HashChainPrivate, val publicAddress: String? = null) {
    companion object {
        fun generateKeyPair(secureRandom: SecureRandom = newSecureRandom(), publicAddress: String? = null): SphinxIdentityKeyPair {
            val signingKeys = generateEdDSAKeyPair(secureRandom)
            val dhKeys = generateCurve25519DHKeyPair(secureRandom)
            val hashChain = HashChainPrivate.generateChain(concatByteArrays(signingKeys.public.encoded, dhKeys.public.encoded), secureRandom)
            return SphinxIdentityKeyPair(signingKeys, dhKeys, hashChain, publicAddress)
        }
    }

    init {
        require(diffieHellmanKeys.private.algorithm == "Curve25519")
    }

    fun getChainValue(stepsFromEnd: Int): SecureHash = hashChain.getChainValue(stepsFromEnd)

    val public: SphinxPublicIdentity by lazy { SphinxPublicIdentity(signingKeys.public, diffieHellmanKeys.public, hashChain.public, publicAddress) }

    val id: SecureHash get() = public.id
}