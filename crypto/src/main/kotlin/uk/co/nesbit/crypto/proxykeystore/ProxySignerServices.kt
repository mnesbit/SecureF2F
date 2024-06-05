package uk.co.nesbit.crypto.proxykeystore

import java.security.Provider

internal open class ProxySignerServices private constructor(
    provider: Provider,
    private val algorithmName: String,
    clazz: Class<out ProxySignerServices>
) : Provider.Service(
    provider,
    "Signature",
    algorithmName,
    clazz.name,
    null,
    null
) {
    override fun newInstance(constructorParameter: Any?): Any {
        return ProxySignature(algorithmName)
    }


    class SHA256withRSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA256withRSA",
        SHA256withRSAProxySigner::class.java
    )

    class SHA384withRSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA384withRSA",
        SHA384withRSAProxySigner::class.java
    )

    class SHA512withRSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA512withRSA",
        SHA512withRSAProxySigner::class.java
    )

    class SHA256withRSAandMGF1ProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA256withRSAandMGF1",
        SHA256withRSAandMGF1ProxySigner::class.java
    )

    class SHA384withRSAandMGF1ProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA384withRSAandMGF1",
        SHA384withRSAandMGF1ProxySigner::class.java
    )

    class SHA512withRSAandMGF1ProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA512withRSAandMGF1",
        SHA512withRSAandMGF1ProxySigner::class.java
    )


    class NONEwithECDSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "NONEwithECDSA",
        NONEwithECDSAProxySigner::class.java
    )

    class SHA256withECDSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA256withECDSA",
        SHA256withECDSAProxySigner::class.java
    )

    class SHA384withECDSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA384withECDSA",
        SHA384withECDSAProxySigner::class.java
    )

    class SHA512withECDSAProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "SHA512withECDSA",
        SHA512withECDSAProxySigner::class.java
    )

    class Ed25519ProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "Ed25519",
        Ed25519ProxySigner::class.java
    )

    class Ed448ProxySigner(provider: Provider) : ProxySignerServices(
        provider,
        "Ed448",
        Ed448ProxySigner::class.java
    )
}