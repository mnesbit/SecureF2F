package com.nesbit.network.engine

import com.nesbit.crypto.*
import com.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import com.nesbit.network.api.OverlayAddress
import com.nesbit.network.api.SphinxAddress
import com.nesbit.network.api.services.KeyService
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantLock

class KeyServiceImpl(override val random: SecureRandom = newSecureRandom()) : KeyService {
    private val lock = ReentrantLock()
    private val networkKeys = mutableListOf<SphinxIdentityKeyPair>()
    private val overlayKeys = mutableListOf<KeyPair>()

    init {
        networkKeys += SphinxIdentityKeyPair.generateKeyPair(random)
        overlayKeys += generateEdDSAKeyPair(random)
    }

    override val networkId: SphinxAddress
        get() = synchronized(lock) { SphinxAddress(networkKeys.first().public) }

    override val overlayAddress: OverlayAddress
        get() = synchronized(lock) { OverlayAddress(overlayKeys.first().public) }

    private fun findById(id: SecureHash): SphinxIdentityKeyPair? = networkKeys.singleOrNull { it.id == id }
    private fun findById2(id: SecureHash): KeyPair? = overlayKeys.singleOrNull { SecureHash.secureHash(it.public.encoded) == id }

    override fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey {
        synchronized(lock) {
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
        synchronized(lock) {
            val key = findById(id)
            require(key != null) { "Key id $id not found" }
            return getSharedDHSecret(key!!.diffieHellmanKeys, remotePublicKey)
        }
    }

    override fun getVersion(id: SecureHash): SecureVersion {
        synchronized(lock) {
            val key = findById(id)
            require(key != null) { "Key id $id not found" }
            val version = key!!.hashChain.version
            return SecureVersion(version, key.hashChain.getChainValue(version))
        }
    }

    override fun incrementAndGetVersion(id: SecureHash): SecureVersion {
        synchronized(lock) {
            val key = findById(id)
            require(key != null) { "Key id $id not found" }
            val version = key!!.hashChain.version + 1
            return SecureVersion(version, key.hashChain.getChainValue(version))
        }
    }
}