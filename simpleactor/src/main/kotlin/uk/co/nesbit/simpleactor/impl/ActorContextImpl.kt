package uk.co.nesbit.simpleactor.impl

import org.slf4j.Logger
import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.Props
import uk.co.nesbit.simpleactor.TimerScheduler
import uk.co.nesbit.simpleactor.impl.messages.Unwatch
import uk.co.nesbit.simpleactor.impl.messages.Watch
import java.util.concurrent.atomic.AtomicLong

internal class ActorContextImpl(
    override val system: ActorSystemInternal,
    override val parent: ActorRef,
    override val self: ActorRef,
    override val props: Props,
    override val log: Logger,
    override val timers: TimerScheduler
) : ActorContextInternal {
    companion object {
        val uid = AtomicLong(0L)
    }

    var senderInternal: ActorRef? = null

    override fun setSender(sender: ActorRef?) {
        senderInternal = sender
    }

    override val sender: ActorRef
        get() = senderInternal!!

    override val children: List<ActorRef>
        get() = system.resolve(self).children.map { it.self }


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
        system.resolve(self).createChild(
            props,
            ref
        )
        return ref
    }

    override fun stop(child: ActorRef) {
        require(self.path.child(child.path.name) == child.path) {
            "Can only stop child"
        }
        system.resolve(child).stop()
    }

    override fun watch(other: ActorRef) {
        if (!system.resolve(self).watchers.contains(other)) {
            other.tell(Watch(other, self), self)
        }
    }

    override fun unwatch(other: ActorRef) {
        if (system.resolve(self).watchers.contains(other)) {
            other.tell(Unwatch(other, self), self)
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