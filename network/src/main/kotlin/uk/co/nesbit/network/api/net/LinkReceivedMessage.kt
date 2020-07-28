package uk.co.nesbit.network.api.net

import uk.co.nesbit.network.api.LinkId
import java.time.Instant

class LinkReceivedMessage(val linkId: LinkId, val received: Instant, val msg: ByteArray)