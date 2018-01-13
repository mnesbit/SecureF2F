package com.nesbit.network.api.services

import com.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import com.nesbit.network.api.OverlayAddress
import com.nesbit.network.api.SphinxAddress
import java.security.KeyPair

interface IdentityService {
    val networkId: SphinxAddress
    val networkKeys: SphinxIdentityKeyPair
    val overlayAddress: OverlayAddress
    val overlayKeys: KeyPair
}