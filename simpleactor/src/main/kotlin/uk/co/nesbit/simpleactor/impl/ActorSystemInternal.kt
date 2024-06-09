package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.ActorSystem
import java.util.concurrent.ExecutorService
import java.util.concurrent.ScheduledExecutorService

internal interface ActorSystemInternal : ActorSystem {
    val executor: ExecutorService
    val timerService: ScheduledExecutorService
    fun resolve(ref: ActorRef): ActorLifecycle
    fun sendToDeadLetter(dead: List<MessageEntry>)
}