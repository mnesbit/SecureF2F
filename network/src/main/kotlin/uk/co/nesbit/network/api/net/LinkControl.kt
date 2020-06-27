package uk.co.nesbit.network.api.net

import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.NetworkAddress

data class OpenRequest(val remoteNetworkId: NetworkAddress)
data class CloseRequest(val linkId: LinkId)
class CloseAllRequest

