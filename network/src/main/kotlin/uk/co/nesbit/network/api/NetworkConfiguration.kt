package uk.co.nesbit.network.api


data class NetworkConfiguration(
    val networkId: NetworkAddress,
    val allowDynamicRouting: Boolean,
    val staticRoutes: Set<NetworkAddress>,
    val blackListedSources: Set<NetworkAddress>
)

