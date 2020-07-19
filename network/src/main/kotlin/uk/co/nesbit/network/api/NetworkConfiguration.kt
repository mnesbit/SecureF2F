package uk.co.nesbit.network.api


data class NetworkConfiguration(
        val networkId: Address,
        val bindAddress: Address,
        val allowDynamicRouting: Boolean,
        val staticRoutes: Set<Address>,
        val blackListedSources: Set<Address>
)

