package uk.co.nesbit.simpleactor.impl

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.co.nesbit.simpleactor.*
import uk.co.nesbit.simpleactor.impl.messages.*
import java.util.concurrent.atomic.AtomicReference

internal class ActorLifecycle(
    private val actorSystem: ActorSystemInternal,
    private val parent: ActorRefImpl,
    val self: ActorRefImpl,
    private val props: Props
) : Teller {
    private data class ActorInstance(val actor: Actor, val timers: TimerScheduler)

    private val actorInstance = AtomicReference<ActorInstance?>(null)

    private val log: Logger = LoggerFactory.getLogger(self.toString())
    private val mailbox = MailboxImpl(actorSystem.executor, ::onReceive)
    private val childStats = mutableMapOf<String, Int>()
    private var stopping = false

    val watchers = mutableSetOf<ActorRef>()
    val children = mutableListOf<ActorLifecycle>()
    var stopped = false

    init {
        tellPriority(InitActor, Actor.NoSender)
        mailbox.resume()
    }

    private fun <R> withActorScope(instance: ActorInstance, block: () -> R): R {
        val context = ActorContextImpl(
            actorSystem,
            parent,
            self,
            props,
            log,
            instance.timers
        )
        return context.actorScope(block)
    }

    fun createChild(props: Props, ref: ActorRefImpl) {
        require(ref.path.parent == self.path) {
            "Invalid path $ref doesn't match parent"
        }
        require(children.none { it.self.path.name == ref.path.name }) {
            "Cannot re-use actor name whilst child exists"
        }
        val child = ActorLifecycle(
            actorSystem,
            self,
            ref,
            props
        )
        children += child
    }

    fun stop() {
        log.warn("stop called on $self")
        if (stopped) {
            return
        }
        if (!stopping) {
            tell(PoisonPill, Actor.NoSender)
        }
    }

    private fun stopInternal() {
        log.warn("Stopping $self")
        mailbox.pause()
        val oldActorInstance = actorInstance.getAndSet(null)
        oldActorInstance?.timers?.cancelAll()
        withActorScope(oldActorInstance!!) {
            oldActorInstance.actor.postStop()
        }
        val parentLifecycle = actorSystem.resolve(parent)
        parentLifecycle.tellPriority(ChildStopped(self.path, self.uid), Actor.NoSender)
        for (watcher in watchers) {
            watcher.tell(Terminated(self), Actor.NoSender)
        }
        watchers.clear()
        actorSystem.sendToDeadLetter(mailbox.clear())
        stopped = true
        log.warn("stopped $self")
    }

    private fun restartInternal(reason: Throwable, message: Any) {
        log.warn("restarting $self")
        val newActor = createActorInstance(props.clazz, props.args)
        val newTimers = TimerSchedulerImpl(actorSystem.timerService, self)
        val oldActorInstance = actorInstance.getAndSet(ActorInstance(newActor, newTimers))
        oldActorInstance?.timers?.cancelAll()
        withActorScope(oldActorInstance!!) {
            oldActorInstance.actor.preRestart(reason, message)
            newActor.postRestart(reason)
        }
        log.warn("restarted $self")
    }

    override fun tell(msg: Any, sender: ActorRef) {
        if (stopped) {
            actorSystem.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
            return
        }
        mailbox.tell(msg, sender)
    }

    private fun tellPriority(msg: Any, sender: ActorRef) {
        if (stopped) {
            actorSystem.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
            return
        }
        mailbox.tellPriority(msg, sender)
    }

    private fun onReceive(msg: Any, sender: ActorRef) {
        try {
            var instance = actorInstance.get()
            if (instance == null && msg === InitActor) {
                log.info("Starting actor $self")
                val newActor = createActorInstance(props.clazz, props.args)
                val newTimers = TimerSchedulerImpl(actorSystem.timerService, self)
                val newInstance = ActorInstance(newActor, newTimers)
                val oldActorInstance = actorInstance.getAndSet(newInstance)
                oldActorInstance?.timers?.cancelAll()
                instance = newInstance
            }
            if (instance != null) {
                withActorScope<Unit>(instance) {
                    when (msg) {
                        InitActor -> {
                            instance.actor.preStart()
                        }

                        is PoisonPill -> {
                            stopping = true
                            if (children.isEmpty()) {
                                tellPriority(Stopped(self.path, self.uid), Actor.NoSender)
                            } else {
                                for (child in children) {
                                    child.tellPriority(PoisonPill, self) //async version
                                }
                            }
                        }

                        is Stopped -> {
                            stopInternal()
                        }

                        is ChildStopped -> {
                            log.warn("Child stopped ${msg.oldPath}:${msg.oldUid}")
                            children.removeIf { it.self.path == msg.oldPath && it.self.uid == msg.oldUid }
                            if (stopping && children.isEmpty()) {
                                tellPriority(Stopped(self.path, self.uid), Actor.NoSender)
                            }
                        }

                        is Restart -> {
                            restartInternal(msg.reason, msg.message)
                        }

                        is EscalateException -> {
                            throw msg.ex
                        }

                        is Kill -> {
                            throw ActorKilledException("Actor $self killed by $sender")
                        }

                        is Watch -> {
                            if (msg.watchee != self) {
                                actorSystem.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
                                return@withActorScope
                            }
                            watchers += msg.watcher
                        }

                        is Unwatch -> {
                            if (msg.watchee != self) {
                                actorSystem.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
                                return@withActorScope
                            }
                            watchers -= msg.watcher
                        }

                        else -> {
                            instance.actor.apply {
                                val contextInternal = context as ActorContextInternal
                                try {
                                    contextInternal.setSender(sender)
                                    onReceive(msg)
                                } finally {
                                    contextInternal.setSender(null)
                                }
                            }
                        }
                    }
                }
            }
        } catch (ex: Throwable) {
            log.error("Actor $self threw exception ${ex.message} while processing ${msg.javaClass.name}")
            if (!stopping) { //ignore errors during close
                handleError(ex)
            }
        }
    }

    private fun handleError(ex: Throwable) {
        val parentLifecycle = actorSystem.resolve(parent)
        val parentInstance = parentLifecycle.actorInstance.get()
        if (parentInstance == null) {
            log.error("Unable to locate parent")
        } else {
            val parentContext = ActorContextImpl(
                actorSystem,
                parentLifecycle.parent,
                parentLifecycle.self,
                parentLifecycle.props,
                parentLifecycle.log,
                parentInstance.timers
            )
            val responseType = parentContext.actorScope {
                parentInstance.actor.supervisorStrategy(
                    parentContext,
                    self,
                    ex,
                    childStats
                )
            }
            parentLifecycle.childStats.compute(self.toString()) { _, v ->
                if (v != null) v + 1 else 1
            }
            when (responseType) {
                SupervisorResponse.Escalate -> {
                    parentLifecycle.tellPriority(EscalateException(ex), Actor.NoSender)
                }

                SupervisorResponse.RestartChild -> {
                    tellPriority(Restart(ex, ""), Actor.NoSender)
                }

                SupervisorResponse.StopChild -> {
                    tellPriority(PoisonPill, Actor.NoSender)
                }
            }
        }
    }
}