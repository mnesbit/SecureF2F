package uk.co.nesbit.network.engine

import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.OverlayAddress
import uk.co.nesbit.network.api.services.KeyService
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class KeyServiceImpl(override val random: SecureRandom = newSecureRandom()) : KeyService {
    private val lock = ReentrantLock()
    private val networkKeys = mutableMapOf<SecureHash, SphinxIdentityKeyPair>()
    private val overlayKeys = mutableMapOf<SecureHash, KeyPair>()

    override fun generateNetworkID(publicAddress: String?): SecureHash {
        val newNetworkKeys = SphinxIdentityKeyPair.generateKeyPair(random, publicAddress = publicAddress)
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
        lock.withLock {
            val key = findById(id)
            if (key != null) {
                return key.signingKeys.sign(bytes)
            }
            val overlayKey = findById2(id)
            require(overlayKey != null) { "Key id $id not found" }
            return overlayKey!!.sign(bytes)
        }
    }

    override fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray {
        lock.withLock {
            val key = findById(id)
            require(key != null) { "Key id $id not found" }
            return getSharedDHSecret(key!!.diffieHellmanKeys, remotePublicKey)
        }
    }

    override fun getVersion(id: SecureHash): VersionedIdentity {
        lock.withLock {
            val key = findById(id)
            require(key != null) { "Key id $id not found" }
            val version = key!!.hashChain.version
            return key.getVersionedId(version)
        }
    }

    override fun incrementAndGetVersion(id: SecureHash): VersionedIdentity {
        lock.withLock {
            val key = findById(id)
            require(key != null) { "Key id $id not found" }
            val version = key!!.hashChain.version + 1
            return key.getVersionedId(version)
        }
    }

    override fun getOverlayAddress(id: SecureHash): OverlayAddress {
        lock.withLock {
            val keys = findById2(id)
            require(keys != null) { "Key id $id not found" }
            return OverlayAddress(keys!!.public)
        }
    }
}