package uk.co.nesbit.network.api.services

import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.Message
import rx.Observable

data class ReceivedMessage(val source: Address, val msg: Message)

interface MessagingService {
    val localAddress: Address
    val knownAddresses: Set<Address>
    fun send(target: Address, msg: Message)
    val onReceive: Observable<ReceivedMessage>
}