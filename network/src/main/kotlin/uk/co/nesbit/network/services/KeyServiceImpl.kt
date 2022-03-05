package uk.co.nesbit.network.services

import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.services.KeyService
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

class KeyServiceImpl(
        override val random: SecureRandom = newSecureRandom(),
        val maxVersion: Int = HashChainPublic.MAX_CHAIN_LENGTH,
        val minVersion: Int = HashChainPublic.MIN_CHAIN_LENGTH
) : KeyService {
    private val networkKeys = ConcurrentHashMap<SecureHash, SphinxIdentityKeyPair>()
    private val signingKeys = ConcurrentHashMap<SecureHash, KeyPair>()
    private val dhKeys = ConcurrentHashMap<SecureHash, KeyPair>()

    override fun generateNetworkID(publicAddress: String?): SecureHash {
        val newNetworkKeys = SphinxIdentityKeyPair.generateKeyPair(
            random,
            publicAddress = publicAddress,
            maxVersion = maxVersion,
            minVersion = minVersion
        )
        networkKeys[newNetworkKeys.id] = newNetworkKeys
        return newNetworkKeys.id
    }

    override fun generateSigningKey(): SecureHash {
        val newSigningKeys = generateNACLKeyPair(random)
        val newId = newSigningKeys.public.id
        signingKeys[newId] = newSigningKeys
        return newId
    }

    override fun generateDhKey(): SecureHash {
        val newDhKeys = generateNACLDHKeyPair(random)
        val newId = newDhKeys.public.id
        dhKeys[newId] = newDhKeys
        return newId
    }

    private fun findSphinxById(id: SecureHash): SphinxIdentityKeyPair? = networkKeys[id]
    private fun findSigningById(id: SecureHash): KeyPair? = signingKeys[id]
    private fun findDhById(id: SecureHash): KeyPair? = dhKeys[id]

    override fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey {
        val key = findSphinxById(id)
        if (key != null) {
            return key.signingKeys.sign(bytes)
        }
        val signingKey = findSigningById(id)
        require(signingKey != null) { "Key id $id not found" }
        return signingKey.sign(bytes)
    }

    override fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray {
        val key = findSphinxById(id)
        if (key != null) {
            return getSharedDHSecret(key.diffieHellmanKeys, remotePublicKey)
        }
        val dhKey = findDhById(id)
        require(dhKey != null) { "Key id $id not found" }
        return getSharedDHSecret(dhKey, remotePublicKey)
    }

    override fun getVersion(id: SecureHash): VersionedIdentity {
        val key = findSphinxById(id)
        require(key != null) { "Key id $id not found" }
        val version = key.hashChain.version
        return key.getVersionedId(version)
    }

    override fun incrementAndGetVersion(id: SecureHash): VersionedIdentity {
        val key = findSphinxById(id)
        require(key != null) { "Key id $id not found" }
        val version = key.hashChain.version + 1
        return key.getVersionedId(version)
    }

    override fun getSigningKey(id: SecureHash): PublicKey {
        val keys = findSigningById(id)
        require(keys != null) { "Key id $id not found" }
        return keys.public
    }

    override fun getDhKey(id: SecureHash): PublicKey {
        val keys = findDhById(id)
        require(keys != null) { "Key id $id not found" }
        return keys.public
    }
}