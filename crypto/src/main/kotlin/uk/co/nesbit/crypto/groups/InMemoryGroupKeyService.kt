package uk.co.nesbit.crypto.groups

import uk.co.nesbit.crypto.*
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

class InMemoryGroupKeyService(
    override val random: SecureRandom = newSecureRandom()
) : GroupKeyService {
    private val signingKeys = ConcurrentHashMap<SecureHash, KeyPair>()
    private val dhKeys = ConcurrentHashMap<SecureHash, KeyPair>()

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

    private fun findSigningById(id: SecureHash): KeyPair? = signingKeys[id]
    private fun findDhById(id: SecureHash): KeyPair? = dhKeys[id]

    override fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey {
        val signingKey = findSigningById(id)
        require(signingKey != null) { "Key id $id not found" }
        return signingKey.sign(bytes)
    }

    override fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray {
        val dhKey = findDhById(id)
        require(dhKey != null) { "Key id $id not found" }
        return getSharedDHSecret(dhKey, remotePublicKey)
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