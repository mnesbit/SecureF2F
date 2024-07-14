package uk.co.nesbit.network.api

import java.security.KeyStore


data class NetworkConfiguration(
        val networkId: Address,
        val bindAddress: Address,
        val allowDynamicRouting: Boolean,
        val staticRoutes: Set<Address>,
        val denyListedSources: Set<Address>,
        val trustStore: KeyStore? = null,
        val keyStore: CertificateStore? = null
)

