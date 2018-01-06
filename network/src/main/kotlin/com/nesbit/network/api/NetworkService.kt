package com.nesbit.network.api

import rx.Observable

data class ReceivedMessage(val sourceLink: LinkId, val msg: Message)

interface NetworkService {
    val localAddress: Address
    fun send(linkId: LinkId, msg: Message)
    fun findLinkTo(target: Address): LinkId?
    val onReceive: Observable<ReceivedMessage>

    val links: Map<LinkId, LinkInfo>
    val onLinkStatusChange: Observable<LinkStatusChange>

    fun openLink(remoteAddress: Address): Boolean
}