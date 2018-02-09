package uk.co.nesbit.network.api.services

import uk.co.nesbit.crypto.DigitalSignatureAndKey
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.SecureVersion
import uk.co.nesbit.network.api.OverlayAddress
import uk.co.nesbit.network.api.SphinxAddress
import java.security.PublicKey
import java.security.SecureRandom

interface KeyService {
    val random: SecureRandom
    val networkId: SphinxAddress
    val overlayAddress: OverlayAddress
    fun sign(id: SecureHash, bytes: ByteArray): DigitalSignatureAndKey
    fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray
    fun getVersion(id: SecureHash): SecureVersion
    fun incrementAndGetVersion(id: SecureHash): SecureVersion
}