package uk.co.nesbit.network.api.net

import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.LinkId

data class OpenRequest(val remoteNetworkId: Address)
data class CloseRequest(val linkId: LinkId)
class CloseAllRequest

