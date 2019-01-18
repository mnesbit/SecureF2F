package uk.co.nesbit.network.api.routing

import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.VersionedAddress

data class Heartbeat(val from: VersionedAddress) : Message