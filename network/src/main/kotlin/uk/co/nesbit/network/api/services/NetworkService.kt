package uk.co.nesbit.network.api.services

import io.reactivex.Observable
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.LinkInfo

data class LinkReceivedMessage(val linkId: LinkId, val msg: ByteArray)

interface NetworkService {
    val networkId: Address
    fun send(linkId: LinkId, msg: ByteArray)
    val onReceive: Observable<LinkReceivedMessage>

    val links: Map<LinkId, LinkInfo>
    val onLinkStatusChange: Observable<LinkInfo>

    fun openLink(remoteAddress: Address): Boolean
    fun closeLink(linkId: LinkId)
}
