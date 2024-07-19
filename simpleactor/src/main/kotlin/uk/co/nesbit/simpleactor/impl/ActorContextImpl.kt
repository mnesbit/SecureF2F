package uk.co.nesbit.simpleactor.impl

import org.slf4j.Logger
import uk.co.nesbit.simpleactor.*
import uk.co.nesbit.simpleactor.impl.messages.Unwatch
import uk.co.nesbit.simpleactor.impl.messages.Watch
import java.util.concurrent.atomic.AtomicLong

internal class ActorContextImpl(
    override val system: ActorSystemInternal,
    override val parent: ActorRef,
    private val selfLifecycle: ActorLifecycle,
    override val props: Props,
    override val log: Logger,
    override val timers: TimerScheduler
) : ActorContextInternal {
    companion object {
        val uid = AtomicLong(0L)
    }

    override val self: ActorRef
        get() = selfLifecycle.self

    private var senderInternal: ActorRef? = null

    override fun setSender(sender: ActorRef?) {
        senderInternal = sender
    }

    override val sender: ActorRef
        get() = senderInternal!!

    override val children: List<ActorRef>
        get() = selfLifecycle.getChildSnapshot().map { it.self }

    override fun getChild(name: String): ActorRef? {
        val childPath = self.path.child(name)
        return children.firstOrNull { it.path == childPath }
    }

    override fun actorOf(props: Props, name: String): ActorRef {
        require(!(name.isBlank() || name.contains("$"))) {
            "Invalid name for actor $name"
        }
        return actorOfInternal(name, props)
    }

    override fun actorOf(props: Props): ActorRef {
        val name = "$" + uid.getAndIncrement()
        return actorOfInternal(name, props)
    }

    private fun actorOfInternal(
        name: String,
        props: Props
    ): ActorRefImpl {
        val ref = ActorRefImpl.createActorRef(system, self.path.child(name))
        selfLifecycle.createChild(
            props,
            ref
        )
        return ref
    }

    override fun stop(other: ActorRef) {
        if (other == self) {
            selfLifecycle.stop()
        } else {
            other.tell(PoisonPill, self)
        }
    }

    override fun watch(other: ActorRef) {
        other.tell(Watch(other, self), self)
    }

    override fun unwatch(other: ActorRef) {
        other.tell(Unwatch(other, self), self)
    }

    override fun actorSelection(path: ActorPath): ActorSelection = actorSelection(path.address)

    override fun actorSelection(path: String): ActorSelection {
        return if (path.startsWith("/")) {
            ActorSelectionImpl(system, path)
        } else {
            ActorSelectionImpl(system, self.path.address + "/" + path)
        }
    }
}

internal val currentContext = ThreadLocal.withInitial<ActorContextInternal?> { null }

internal fun currentActorContextInternal(): ActorContextInternal? {
    return currentContext.get()
}

internal fun <R> ActorContextInternal.actorScope(block: () -> R): R {
    val prevScope = currentContext.get()
    try {
        currentContext.set(this)
        return block()
    } finally {
        currentContext.set(prevScope)
    }
}