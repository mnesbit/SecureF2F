package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorRef

internal fun interface Teller {
    fun tell(msg: Any, sender: ActorRef)
}

internal fun interface MailHandler {
    fun onReceive(msg: Any, sender: ActorRef)
}

internal data class MessageEntry(
    val msg: Any,
    val sender: ActorRef
)

internal interface MailBox : Teller {
    fun tellPriority(msg: Any, sender: ActorRef)
    fun pause()
    fun resume()
    fun clear(): List<MessageEntry>
    fun inHandler(): Boolean
}