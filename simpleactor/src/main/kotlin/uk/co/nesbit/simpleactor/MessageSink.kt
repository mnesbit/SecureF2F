package uk.co.nesbit.simpleactor

fun interface MessageHandler {
    fun onMessage(self: ActorRef, msg: Any, sender: ActorRef)
}

interface MessageSink : ActorRef, AutoCloseable, MessageHandler