package uk.co.nesbit.crypto.proxykeystore

import java.security.Provider
import java.security.Security

class ProxyKeyStoreProvider : Provider(
    ProviderName,
    "1.0.0",
    "Keystore that proxies signing"
) {
    companion object {
        private const val ProviderName = "ProxyKeyStoreProvider"
        const val ProviderKeystoreType = "PROXY"

        init {
            install()
        }

        fun install() {
            val existing = Security.getProvider(ProviderName) as ProxyKeyStoreProvider?
            if (existing == null) {
                Security.addProvider(ProxyKeyStoreProvider())
            }
        }

    }

    init {
        this["KeyStore.$ProviderKeystoreType"] = ProxyKeyStoreProvider::class.java.name
        putService(ProxyKeyStoreService())
        putService(ProxySignerServices.SHA256withRSAProxySigner(this))
        putService(ProxySignerServices.SHA384withRSAProxySigner(this))
        putService(ProxySignerServices.SHA512withRSAProxySigner(this))
        putService(ProxySignerServices.SHA256withRSAandMGF1ProxySigner(this))
        putService(ProxySignerServices.SHA384withRSAandMGF1ProxySigner(this))
        putService(ProxySignerServices.SHA512withRSAandMGF1ProxySigner(this))
        putService(ProxySignerServices.NONEwithECDSAProxySigner(this))
        putService(ProxySignerServices.SHA256withECDSAProxySigner(this))
        putService(ProxySignerServices.SHA384withECDSAProxySigner(this))
        putService(ProxySignerServices.SHA512withECDSAProxySigner(this))
        putService(ProxySignerServices.Ed25519ProxySigner(this))
        putService(ProxySignerServices.Ed448ProxySigner(this))
    }

    private inner class ProxyKeyStoreService : Service(
        this@ProxyKeyStoreProvider,
        "KeyStore",
        ProviderKeystoreType,
        "uk.co.nesbit.crypto.proxykeystore.ProxyKeyStoreProvider\$ProxyKeyStoreService",
        null,
        null
    ) {
        override fun newInstance(constructorParameter: Any?): Any {
            return ProxyKeyStore()
        }
    }

}