package uk.co.nesbit.simpleactor.impl

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.co.nesbit.simpleactor.*
import uk.co.nesbit.simpleactor.impl.messages.*
import java.util.concurrent.atomic.AtomicReference

internal class ActorLifecycle(
    private val system: ActorSystemInternal,
    var parentLifecycle: ActorLifecycle?,
    val self: ActorRefImpl,
    private val props: Props
) : Teller {
    private data class ActorInstance(val actor: Actor, val timers: TimerScheduler, val context: ActorContextInternal)

    private val actorInstance = AtomicReference<ActorInstance?>(null)

    private val log: Logger = LoggerFactory.getLogger(self.toString())
    private val mailbox = system.createMailBox(::onReceive)
    private var stopping = false

    private val parent: ActorRef
        get() = parentLifecycle!!.self

    private val watchers = mutableSetOf<ActorRef>()
    private val childStats = mutableMapOf<String, Int>()
    private val children = mutableListOf<ActorLifecycle>()
    var stopped = false

    fun start() {
        require(parentLifecycle != null) {
            "parent not set"
        }
        tellPriority(InitActor, Actor.NoSender)
        mailbox.resume()
    }

    fun createChild(props: Props, ref: ActorRefImpl) {
        mailbox.runExclusive {
            require(ref.path.parent == self.path) {
                "Invalid path $ref doesn't match parent"
            }
            require(children.none { it.self.path.name == ref.path.name }) {
                "Cannot re-use actor name whilst child exists"
            }
            val child = ActorLifecycle(
                system,
                this,
                ref,
                props
            )
            children += child
            child.start()
        }
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
        oldActorInstance?.context?.actorScope {
            oldActorInstance.actor.postStop()
        }
        oldActorInstance?.timers?.cancelAll()
        parentLifecycle!!.tellPriority(ChildStopped(self.path, self.uid, watchers.toMutableList()), Actor.NoSender)
        watchers.clear() //responsibility passed to parent
        system.sendToDeadLetter(mailbox.clear())
        stopped = true
        log.warn("stopped $self")
    }

    private fun restartInternal(reason: Throwable, message: Any?) {
        log.warn("restarting $self")
        val newActor = createActorInstance(props.clazz, props.args)
        val newTimers = TimerSchedulerImpl(system.timerService, self)
        val newContext = ActorContextImpl(
            system,
            parent,
            this,
            props,
            log,
            newTimers
        )
        val oldActorInstance = actorInstance.getAndSet(ActorInstance(newActor, newTimers, newContext))
        oldActorInstance?.context?.actorScope {
            oldActorInstance.actor.preRestart(reason, message)
        }
        newContext.actorScope {
            newActor.postRestart(reason)
        }
        oldActorInstance?.timers?.cancelAll()
        log.warn("restarted $self")
    }

    override fun tell(msg: Any, sender: ActorRef) {
        if (stopped) {
            system.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
            return
        }
        mailbox.tell(msg, sender)
    }

    fun getChildSnapshot(): List<ActorLifecycle> {
        return mailbox.runExclusive { children.toMutableList() }
    }

    fun getWatcherSnapshot(): List<ActorRef> {
        return mailbox.runExclusive { watchers.toMutableList() }
    }

    private fun tellPriority(msg: Any, sender: ActorRef) {
        if (stopped) {
            system.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
            return
        }
        mailbox.tellPriority(msg, sender)
    }

    private fun onReceive(msg: Any, sender: ActorRef) {
        try {
            var instance = actorInstance.get()
            if (instance == null && msg === InitActor) {
                log.info("Starting actor $self")
                val newTimers = TimerSchedulerImpl(system.timerService, self)
                val newContext = ActorContextImpl(
                    system,
                    parent,
                    this,
                    props,
                    log,
                    newTimers
                )
                val newActor = newContext.actorScope {
                    createActorInstance(props.clazz, props.args)
                }
                val newInstance = ActorInstance(newActor, newTimers, newContext)
                val oldActorInstance = actorInstance.getAndSet(newInstance)
                oldActorInstance?.timers?.cancelAll()
                instance = newInstance
            }
            instance?.context?.actorScope {
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
                        val childRef = ActorRefImpl(system, msg.oldPath, msg.oldUid)
                        // On behalf of child signal their watcher after concrete child removal to avoid race on recreate
                        for (watcher in msg.watchList) {
                            watcher.tell(Terminated(childRef), Actor.NoSender)
                        }
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
                            system.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
                            return@actorScope
                        }
                        watchers += msg.watcher
                    }

                    is Unwatch -> {
                        if (msg.watchee != self) {
                            system.sendToDeadLetter(listOf(MessageEntry(msg, sender)))
                            return@actorScope
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
        } catch (ex: Throwable) {
            log.error("Actor $self threw exception ${ex} while processing ${msg.javaClass.name}", ex)
            if (!stopping) { //ignore errors during close
                handleError(ex, msg)
            }
        }
    }

    private fun handleError(ex: Throwable, msg: Any?) {
        val parentTemp = parentLifecycle!!
        val parentInstance = parentTemp.actorInstance.get()
        if (parentInstance == null) {
            log.error("Unable to locate parent")
        } else {
            val parentContext = ActorContextImpl(
                system,
                parentTemp.parent,
                parentTemp,
                parentTemp.props,
                parentTemp.log,
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
            parentTemp.childStats.compute(self.toString()) { _, v ->
                if (v != null) v + 1 else 1
            }
            when (responseType) {
                SupervisorResponse.Escalate -> {
                    parentTemp.tellPriority(EscalateException(ex), Actor.NoSender)
                }

                SupervisorResponse.Ignore -> {
                    log.warn("Ignoring exception $ex")
                }

                SupervisorResponse.RestartChild -> {
                    tellPriority(Restart(ex, msg), Actor.NoSender)
                }

                SupervisorResponse.StopChild -> {
                    tellPriority(PoisonPill, Actor.NoSender)
                }
            }
        }
    }

    override fun toString(): String = "ActorLifeCycle[${self.path}]"
}