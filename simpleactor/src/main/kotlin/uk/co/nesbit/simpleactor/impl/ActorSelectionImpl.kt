package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorContext
import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.ActorSelection

internal class ActorSelectionImpl(
    private val system: ActorSystemInternal,
    override val pathString: String
) : ActorSelection {
    override fun resolve(): List<ActorRef> {
        return system.resolveAddress(pathString)
    }

    override fun tell(msg: Any, sender: ActorRef) {
        val selection = resolve()
        selection.forEach { it.tell(msg, sender) }
    }

    override fun forward(msg: Any, context: ActorContext) {
        val selection = resolve()
        selection.forEach { it.tell(msg, context.sender) }
    }
}