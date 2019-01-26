package uk.co.nesbit.network.api.services

import io.reactivex.Observable
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.Message

data class ReceivedMessage(val source: Address, val msg: Message)

interface MessagingService {
    val localAddress: Address
    val knownAddresses: Set<Address>
    fun send(target: Address, msg: Message)
    val onReceive: Observable<ReceivedMessage>
}