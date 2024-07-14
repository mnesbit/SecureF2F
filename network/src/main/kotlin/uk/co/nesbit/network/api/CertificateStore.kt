package uk.co.nesbit.network.api

import java.security.KeyStore

data class CertificateStore(
    val keystore: KeyStore,
    val entryPassword: String?
)