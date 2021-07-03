package uk.co.nesbit.network.api.services

import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import java.security.PublicKey
import java.security.SecureRandom

interface KeyService {
    val random: SecureRandom
    fun generateNetworkID(publicAddress: String? = null): SecureHash
    fun generateSigningKey(): SecureHash
    fun generateDhKey(): SecureHash
    fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey
    fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray
    fun getVersion(id: SecureHash): VersionedIdentity
    fun incrementAndGetVersion(id: SecureHash): VersionedIdentity
    fun getSigningKey(id: SecureHash): PublicKey
    fun getDhKey(id: SecureHash): PublicKey
}