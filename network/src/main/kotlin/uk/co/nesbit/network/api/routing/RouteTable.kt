package uk.co.nesbit.network.api.routing

import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.util.BloomFilter

class RouteTable(val fullRoutes: List<Routes>, val knownAddresses: BloomFilter, val replyTo: Address?) : Message

