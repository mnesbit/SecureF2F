package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.ActorSystem
import java.util.concurrent.ScheduledExecutorService

internal interface ActorSystemInternal : ActorSystem {
    val timerService: ScheduledExecutorService
    fun createMailBox(handler: MailHandler): MailBox
    fun resolve(ref: ActorRef): ActorLifecycle
    fun resolveAddress(pathFromRoot: String): List<ActorRef>
    fun sendToDeadLetter(dead: List<MessageEntry>)
}