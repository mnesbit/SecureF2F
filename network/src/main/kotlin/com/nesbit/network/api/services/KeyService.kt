package com.nesbit.network.api.services

import com.nesbit.crypto.DigitalSignature
import com.nesbit.crypto.SecureHash
import com.nesbit.network.api.OverlayAddress
import com.nesbit.network.api.SphinxAddress
import java.security.PublicKey
import java.security.SecureRandom

data class SecureVersion(val version: Int, val chainHash: SecureHash)

interface KeyService {
    val random: SecureRandom
    val networkId: SphinxAddress
    val overlayAddress: OverlayAddress
    fun sign(id: SecureHash, bytes: ByteArray): DigitalSignature
    fun getSharedDHSecret(id: SecureHash, remotePublicKey: PublicKey): ByteArray
    fun getVersion(id: SecureHash): SecureVersion
    fun incrementAndGetVersion(id: SecureHash): SecureVersion
}