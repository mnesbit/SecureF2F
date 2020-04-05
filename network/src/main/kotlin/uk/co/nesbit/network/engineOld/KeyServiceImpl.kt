package uk.co.nesbit.network.engineOld

import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.OverlayAddress
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
    private val overlayKeys = ConcurrentHashMap<SecureHash, KeyPair>()

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

    override fun generateOverlayID(): SecureHash {
        val newOverlayKeys = generateECDSAKeyPair(random)
        val newId = SecureHash.secureHash(newOverlayKeys.public.encoded)
        overlayKeys[newId] = newOverlayKeys
        return newId
    }

    private fun findById(id: SecureHash): SphinxIdentityKeyPair? = networkKeys[id]
    private fun findById2(id: SecureHash): KeyPair? = overlayKeys[id]

    override fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey {
        val key = findById(id)
        if (key != null) {
            return key.signingKeys.sign(bytes)
        }
        val overlayKey = findById2(id)
        require(overlayKey != null) { "Key id $id not found" }
        return overlayKey.sign(bytes)

    }

    override fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray {
        val key = findById(id)
        require(key != null) { "Key id $id not found" }
        return getSharedDHSecret(key.diffieHellmanKeys, remotePublicKey)
    }

    override fun getVersion(id: SecureHash): VersionedIdentity {
        val key = findById(id)
        require(key != null) { "Key id $id not found" }
        val version = key.hashChain.version
        return key.getVersionedId(version)
    }

    override fun incrementAndGetVersion(id: SecureHash): VersionedIdentity {
        val key = findById(id)
        require(key != null) { "Key id $id not found" }
        val version = key.hashChain.version + 1
        return key.getVersionedId(version)
    }

    override fun getOverlayAddress(id: SecureHash): OverlayAddress {
        val keys = findById2(id)
        require(keys != null) { "Key id $id not found" }
        return OverlayAddress(keys.public)
    }
}