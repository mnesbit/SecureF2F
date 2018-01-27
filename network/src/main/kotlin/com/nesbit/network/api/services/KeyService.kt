package com.nesbit.network.api.services

import com.nesbit.crypto.DigitalSignatureAndKey
import com.nesbit.crypto.SecureHash
import com.nesbit.crypto.SecureVersion
import com.nesbit.network.api.OverlayAddress
import com.nesbit.network.api.SphinxAddress
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