package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorContext
import uk.co.nesbit.simpleactor.ActorRef

internal interface ActorContextInternal : ActorContext {
    fun setSender(sender: ActorRef?)
}