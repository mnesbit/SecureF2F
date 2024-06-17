package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.*

internal class MessageSinkActor(handler: MessageHandler) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(handler: MessageHandler): Props {
            return createProps(MessageSinkActor::class.java, handler)
        }
    }

    object RequestSink

    private class SinkWrapper(val parent: ActorRef, val handler: MessageHandler) : MessageSink {
        override val path: ActorPath
            get() = parent.path

        override fun tell(msg: Any, sender: ActorRef) {
            parent.tell(msg, sender)
        }

        override fun forward(msg: Any, context: ActorContext) {
            parent.forward(msg, context)
        }

        override fun close() {
            parent.tell(PoisonPill, Actor.NoSender)
        }

        override fun onMessage(self: ActorRef, msg: Any, sender: ActorRef) {
            handler.onMessage(self, msg, sender)
        }

    }

    private val sink = SinkWrapper(self, handler)

    override fun onReceive(message: Any) {
        when (message) {
            is RequestSink -> {
                sender.tell(sink)
            }

            else -> sink.onMessage(self, message, sender)
        }
    }
}