package uk.co.nesbit.network.api

data class LinkSendMessage(val linkId: LinkId, val msg: ByteArray)