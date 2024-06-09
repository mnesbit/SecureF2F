package uk.co.nesbit.simpleactor.impl

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import org.slf4j.LoggerFactory
import uk.co.nesbit.simpleactor.ActorPath
import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.Props
import uk.co.nesbit.simpleactor.Terminated
import uk.co.nesbit.simpleactor.impl.messages.Watch
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import kotlin.math.min

internal class ActorSystemImpl(
    override val name: String,
    override val config: Config
) : ActorSystemInternal {
    companion object {
        private val defaultConfig = ConfigFactory.parseString(
            """
                SimpleActor {
                    executor {
                        type = ForkJoin
                    }
                }
            """
        )
    }

    private val log = LoggerFactory.getLogger("System:$name")
    private val rootActor: ActorLifecycle
    private val root: ActorRef
    override val executor: ExecutorService
    override val timerService: ScheduledExecutorService

    init {
        when (config.withFallback(defaultConfig).getString("SimpleActor.executor.type")) {
            "ForkJoin" -> executor = Executors.newWorkStealingPool()
            "Single" -> executor = Executors.newSingleThreadExecutor()
            else -> throw IllegalArgumentException("Unrecognized executor type")
        }
        timerService = Executors.newSingleThreadScheduledExecutor()
        val rootRef = ActorRefImpl.createActorRef(
            this,
            ActorPath(
                "SimpleActor://$name"
            )
        )
        rootActor = ActorLifecycle(
            this,
            rootRef,
            rootRef,
            RootActor.getProps()
        )
        root = rootActor.self
        log.info("System $name starting")
    }

    override fun actorOf(props: Props, name: String): ActorRef {
        require(!(name.isBlank() || name.contains("$"))) {
            "Invalid name for actor $name"
        }
        return actorOfInternal(props, name)
    }

    override fun actorOf(props: Props): ActorRef {
        val name = "$" + ActorContextImpl.uid.getAndIncrement()
        return actorOfInternal(props, name)
    }

    private fun actorOfInternal(props: Props, name: String): ActorRef {
        val ref = ActorRefImpl.createActorRef(
            this,
            root.path.child(name)
        )
        rootActor.createChild(
            props,
            ref
        )
        return ref
    }

    override fun stop(actor: ActorRef) {
        try {
            val doneFut = CompletableFuture<Terminated>()
            val waitDone = WaitForReplyActorRef(Terminated::class.java, doneFut)
            actor.tell(Watch(actor, waitDone), waitDone)
            resolve(actor).stop()
            doneFut.get()
        } catch (ex: Exception) {
            log.warn("Couldn't find $actor to stop")
        }
    }

    override fun stop() {
        rootActor.stop()
        while (!rootActor.stopped) {
            Thread.sleep(100L)
        }
        timerService.shutdown()
        executor.shutdown()
    }

    override fun sendToDeadLetter(dead: List<MessageEntry>) {
        if (dead.isNotEmpty()) {
            log.warn("dumping ${dead.size} messages to dead letter ${dead.joinToString { it.msg.javaClass.name }}")
        }
    }

    override fun resolve(ref: ActorRef): ActorLifecycle {
        require(ref.path.address.startsWith(root.path.address)) {
            "Cannot resolve $ref for different system"
        }
        var current = rootActor
        val targetStr = ref.path.address
        while (current.self.path != ref.path) {
            var found = false
            for (child in current.children) {
                val childStr = child.self.path.address
                if (childStr == targetStr.substring(0, min(childStr.length, targetStr.length))) {
                    current = child
                    found = true
                    break
                }
            }
            if (!found) {
                throw IllegalArgumentException("Unknown actor $ref")
            }
        }
        if (current.self != ref) {
            throw IllegalArgumentException("Actor instance $ref dead")
        }
        return current
    }
}