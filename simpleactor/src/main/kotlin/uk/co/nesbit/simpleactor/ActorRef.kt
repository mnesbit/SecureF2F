package uk.co.nesbit.simpleactor

import uk.co.nesbit.simpleactor.impl.askInternal
import java.util.concurrent.Future

interface ActorRef {
    val path: ActorPath
    fun tell(msg: Any, sender: ActorRef = currentActorContext()?.self ?: Actor.NoSender)
    fun forward(msg: Any, context: ActorContext = currentActorContext()!!)
}

inline fun <reified R> ActorRef.ask(msg: Any): Future<R> {
    return askInternal(this, msg, R::class.java)
}