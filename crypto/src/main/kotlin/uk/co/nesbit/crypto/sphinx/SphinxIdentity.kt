package uk.co.nesbit.crypto.sphinx

import org.apache.avro.Schema
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import uk.co.nesbit.avro.*
import uk.co.nesbit.crypto.*
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom

class SphinxPublicIdentity(
    val signingPublicKey: PublicKey,
    val diffieHellmanPublicKey: PublicKey,
    val targetHash: SecureHash,
    val maxVersion: Int,
    val minVersion: Int,
    val publicAddress: String?
) : AvroConvertible {
    constructor(signatureRecord: GenericRecord) :
            this(
                signatureRecord.getTyped("signingPublicKey"),
                signatureRecord.getTyped("diffieHellmanPublicKey"),
                signatureRecord.getTyped("targetHash"),
                signatureRecord.getTyped("maxVersion"),
                signatureRecord.getTyped("minVersion"),
                signatureRecord.getTyped<String?>("publicAddress")
            )

    companion object {
        const val ID_HASH_ALGORITHM = "SHA-256"

        @Suppress("JAVA_CLASS_ON_COMPANION")
        val sphinxIdentitySchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    PublicKeyHelper.publicKeySchema.fullName to PublicKeyHelper.publicKeySchema,
                    SecureHash.secureHashSchema.fullName to SecureHash.secureHashSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/sphinx/sphinxidentity.avsc"))

        fun deserialize(bytes: ByteArray): SphinxPublicIdentity {
            val idRecord = sphinxIdentitySchema.deserialize(bytes)
            return SphinxPublicIdentity(idRecord)
        }

    }

    private val hashChain = HashChainPublic(
        concatByteArrays(
            signingPublicKey.encoded,
            diffieHellmanPublicKey.encoded,
            maxVersion.toByteArray(),
            minVersion.toByteArray()
        ), targetHash, maxVersion, minVersion
    )

    init {
        require(diffieHellmanPublicKey.algorithm == "Curve25519")
    }

    override fun toGenericRecord(): GenericRecord {
        val hashChainRecord = GenericData.Record(sphinxIdentitySchema)
        hashChainRecord.putTyped("signingPublicKey", signingPublicKey)
        hashChainRecord.putTyped("diffieHellmanPublicKey", diffieHellmanPublicKey)
        hashChainRecord.putTyped("targetHash", targetHash)
        hashChainRecord.putTyped("maxVersion", maxVersion)
        hashChainRecord.putTyped("minVersion", minVersion)
        hashChainRecord.putTyped("publicAddress", publicAddress)
        return hashChainRecord
    }

    val id: SecureHash by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val bytes = this.serialize()
        bytes.secureHash(ID_HASH_ALGORITHM)
    }

    fun verifyChainValue(version: SecureVersion): Boolean = hashChain.verifyChainValue(version)

    fun verifyChainValue(hash: SecureHash, stepsFromEnd: Int): Boolean =
        hashChain.verifyChainValue(hash, stepsFromEnd, minVersion, maxVersion)

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

class SphinxIdentityKeyPair(
    val signingKeys: KeyPair,
    val diffieHellmanKeys: KeyPair,
    val hashChain: HashChainPrivate,
    val publicAddress: String? = null
) {
    companion object {
        fun generateKeyPair(
            secureRandom: SecureRandom = newSecureRandom(),
            publicAddress: String? = null,
            maxVersion: Int = HashChainPublic.MAX_CHAIN_LENGTH,
            minVersion: Int = HashChainPublic.MIN_CHAIN_LENGTH
        ): SphinxIdentityKeyPair {
            val signingKeys = generateEdDSAKeyPair(secureRandom)
            val dhKeys = generateCurve25519DHKeyPair(secureRandom)
            val hashChain = PebbledHashChain.generateChain(
                concatByteArrays(
                    signingKeys.public.encoded,
                    dhKeys.public.encoded,
                    maxVersion.toByteArray(),
                    minVersion.toByteArray()
                ), secureRandom, maxVersion, minVersion
            )
            return SphinxIdentityKeyPair(signingKeys, dhKeys, hashChain, publicAddress)
        }
    }

    init {
        require(diffieHellmanKeys.private.algorithm == "Curve25519")
    }

    fun getVersionedId(version: Int): VersionedIdentity = VersionedIdentity(public, hashChain.getSecureVersion(version))

    val public: SphinxPublicIdentity by lazy(LazyThreadSafetyMode.PUBLICATION) {
        SphinxPublicIdentity(
            signingKeys.public,
            diffieHellmanKeys.public,
            hashChain.targetHash,
            hashChain.maxChainLength,
            hashChain.minChainLength,
            publicAddress
        )
    }

    val id: SecureHash get() = public.id
}

data class VersionedIdentity(val identity: SphinxPublicIdentity, val currentVersion: SecureVersion) : AvroConvertible {
    constructor(versionRecord: GenericRecord) :
            this(
                versionRecord.getTyped("identity"),
                versionRecord.getTyped("currentVersion")
            )

    init {
        require(identity.verifyChainValue(currentVersion)) { "Invalid version information" }
    }

    val id: SecureHash get() = identity.id

    companion object {
        @Suppress("JAVA_CLASS_ON_COMPANION")
        val versionedIdentitySchema: Schema = Schema.Parser()
            .addTypes(
                mapOf(
                    SphinxPublicIdentity.sphinxIdentitySchema.fullName to SphinxPublicIdentity.sphinxIdentitySchema,
                    SecureVersion.secureVersionSchema.fullName to SecureVersion.secureVersionSchema
                )
            )
            .parse(javaClass.enclosingClass.getResourceAsStream("/uk/co/nesbit/crypto/sphinx/versionedidentity.avsc"))

        fun deserialize(bytes: ByteArray): VersionedIdentity {
            val versionedIdentityRecord = versionedIdentitySchema.deserialize(bytes)
            return VersionedIdentity(versionedIdentityRecord)
        }
    }

    override fun toGenericRecord(): GenericRecord {
        val versionedIdentityRecord = GenericData.Record(versionedIdentitySchema)
        versionedIdentityRecord.putTyped("identity", identity)
        versionedIdentityRecord.putTyped("currentVersion", currentVersion)
        return versionedIdentityRecord
    }
}