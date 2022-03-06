package uk.co.nesbit.crypto.groups

import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash
import java.security.PublicKey
import java.security.SecureRandom

interface GroupKeyService {
    val random: SecureRandom
    fun generateSigningKey(): SecureHash
    fun generateDhKey(): SecureHash
    fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey
    fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray
    fun getSigningKey(id: SecureHash): PublicKey
    fun getDhKey(id: SecureHash): PublicKey
    fun destroyKey(id: SecureHash)
}