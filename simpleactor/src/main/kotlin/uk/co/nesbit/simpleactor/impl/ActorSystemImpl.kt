package uk.co.nesbit.simpleactor.impl

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import org.slf4j.LoggerFactory
import uk.co.nesbit.simpleactor.*
import uk.co.nesbit.simpleactor.impl.messages.Watch
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService

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
            null,
            rootRef,
            RootActor.getProps()
        )
        rootActor.parentLifecycle = rootActor
        rootActor.start()
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
            log.warn("dumping ${dead.size} messages to dead letter: ${dead.joinToString { it.msg.javaClass.name }}")
        }
    }

    override val deadLetters: ActorRef = object : ActorRef {
        override val path: ActorPath = ActorPath("${root.path.address}/\$dead")

        override fun tell(msg: Any, sender: ActorRef) {
            sendToDeadLetter(listOf(MessageEntry(msg, sender)))
        }

        override fun forward(msg: Any, context: ActorContext) {
            sendToDeadLetter(listOf(MessageEntry(msg, context.sender)))
        }
    }

    override fun resolve(ref: ActorRef): ActorLifecycle {
        require(ref.path.address.startsWith(root.path.address)) {
            "Cannot resolve $ref for different system"
        }
        var current = rootActor
        val targetStr = ref.path.address
        var levelEnd = targetStr.indexOf('/', rootActor.self.path.address.length + 1)
        if (levelEnd == -1) {
            levelEnd = targetStr.length
        }
        while (current.self.path != ref.path) {
            var found = false
            val levelStr = targetStr.substring(0, levelEnd)
            val children = current.getChildSnapshot()
            for (child in children) {
                val childStr = child.self.path.address
                if (childStr == levelStr) {
                    current = child
                    found = true
                    break
                }
            }
            if (!found) {
                throw IllegalArgumentException("Unknown actor $ref")
            }
            levelEnd = targetStr.indexOf('/', levelEnd + 1)
            if (levelEnd == -1) {
                levelEnd = targetStr.length
            }
        }
        if (current.self != ref) {
            throw IllegalArgumentException("Actor instance $ref dead")
        }
        return current
    }

    override fun resolveAddress(pathFromRoot: String): List<ActorRef> {
        val search = if (pathFromRoot.contains("SimpleActor://")) {
            val root = "SimpleActor://$name/"
            pathFromRoot.substring(root.length - 1)
        } else {
            pathFromRoot
        }
        val levels = search.split("/").drop(1)
        var searchList = listOf(rootActor)
        for (level in levels) {
            val newSet = mutableSetOf<ActorLifecycle>()
            if (level.contains('*') || level.contains('?')) {
                val globAsRegex = buildString {
                    append("^")
                    append(
                        level.replace(".", "\\.")
                            .replace("*", ".*")
                            .replace("?", ".")
                    )
                    append("$")
                }
                val levelRegex = Regex(globAsRegex)
                for (searched in searchList) {
                    if (!searched.stopped) {
                        val children = searched.getChildSnapshot().filter {
                            it.self.path.name.matches(levelRegex)
                        }
                        newSet += children
                    }
                }
            } else if (level == "..") {
                for (searched in searchList) {
                    newSet += searched.parentLifecycle!!
                }
            } else {
                for (searched in searchList) {
                    if (!searched.stopped) {
                        newSet += searched.getChildSnapshot().filter { it.self.path.name == level }
                    }
                }
            }
            searchList = newSet.toList()
            if (searchList.isEmpty()) break
        }
        return searchList.map { it.self }
    }

    override fun actorSelection(path: ActorPath): ActorSelection = actorSelection(path.address)

    override fun actorSelection(path: String): ActorSelection {
        return if (path.startsWith("/")) {
            ActorSelectionImpl(this, path)
        } else {
            ActorSelectionImpl(this, "/$path")
        }
    }

    override fun createMessageSink(handler: MessageHandler): MessageSink {
        val sinkActor = actorOf(MessageSinkActor.getProps(handler))
        return sinkActor.ask<MessageSink>(MessageSinkActor.RequestSink).get()
    }
}