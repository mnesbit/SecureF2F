package uk.co.nesbit.network.api.services

import uk.co.nesbit.network.api.*
import rx.Observable

interface NetworkService {
    val localAddress: Address
    fun send(linkId: LinkId, msg: Message)
    fun findLinkTo(target: Address): LinkId?
    val onReceive: Observable<Message>

    val links: Map<LinkId, LinkInfo>
    val onLinkStatusChange: Observable<LinkStatusChange>

    fun openLink(remoteAddress: Address): Boolean
    fun closeLink(linkId: LinkId)
}
