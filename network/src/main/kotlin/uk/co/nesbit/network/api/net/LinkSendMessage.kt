package uk.co.nesbit.network.api.net

import uk.co.nesbit.network.api.LinkId

class LinkSendMessage(val linkId: LinkId, val msg: ByteArray)

class LinkSendStatus(val linkId: LinkId, val sent: Boolean)