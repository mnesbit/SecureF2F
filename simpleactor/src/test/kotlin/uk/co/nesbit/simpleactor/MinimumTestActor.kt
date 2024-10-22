package uk.co.nesbit.simpleactor

import java.time.Duration

class MinimumTestActorInt(private var count: Int) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(count: Int): Props {
            return createProps(MinimumTestActorInt::class.java, count)
        }
    }

    private var stopRequestor: ActorRef? = null

    override fun onReceive(message: Any) {
        context.log.warn("$message sent by $sender")
        when (message) {
            "CreateChildString" -> {
                val ref = context.actorOf(MinimumTestActorString.getProps("String_$count"), "String")
                sender.tell(ref)
            }

            "CreateChildInt" -> {
                val ref = context.actorOf(MinimumTestActorInt.getProps(count + 1), "Int")
                sender.tell(ref)
            }

            "CreateChildObj" -> {
                val ref = context.actorOf(MinimumTestActorObj.getProps(Thing(count + 1)), "Obj")
                sender.tell(ref)
            }

            "Get" -> {
                sender.tell(count)
            }

            "StopChild" -> {
                val child = context.children.firstOrNull()
                if (child != null) {
                    stopRequestor = sender
                    context.watch(child)
                    context.stop(child)
                } else {
                    sender.tell("OK")
                }
            }

            "StopChild2" -> {
                val child = context.children.firstOrNull()
                if (child != null) {
                    stopRequestor = sender
                    context.watch(child)
                    context.stop(child)
                    context.stop(child)
                } else {
                    sender.tell("OK")
                }
            }

            is Int -> {
                count = message
            }

            is Terminated -> {
                stopRequestor?.tell("OK")
                stopRequestor = null
            }

            else -> throw RuntimeException("Unhandled")
        }
    }
}

class MinimumTestActorString(private var value: String) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(value: String): Props {
            return createProps(MinimumTestActorString::class.java, value)
        }
    }

    override fun onReceive(message: Any) {
        context.log.warn("$message sent by $sender")
        when (message) {
            "CreateChildString" -> {
                val ref = context.actorOf(MinimumTestActorString.getProps("String_$value"), "String")
                sender.tell(ref)
            }

            "CreateChildInt" -> {
                val ref = context.actorOf(MinimumTestActorInt.getProps(value.hashCode()), "Int")
                sender.tell(ref)
            }

            "CreateChildObj" -> {
                val ref = context.actorOf(MinimumTestActorObj.getProps(null), "Obj")
                sender.tell(ref)
            }

            "Get" -> {
                sender.tell(value)
            }

            is String -> {
                value = message
            }

            else -> throw RuntimeException("Unhandled")
        }
    }

}

data class Thing(val count: Int)

class MinimumTestActorObj(private var obj: Thing?) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(obj: Thing?): Props {
            return createProps(MinimumTestActorObj::class.java, obj)
        }
    }

    override fun onReceive(message: Any) {
        context.log.warn("$message sent by $sender")
        when (message) {
            "CreateChildString" -> {
                val ref = context.actorOf(MinimumTestActorString.getProps("String_$obj"), "String")
                sender.tell(ref)
            }

            "CreateChildInt" -> {
                val ref = context.actorOf(MinimumTestActorInt.getProps((obj?.count ?: 0) + 1), "Int")
                sender.tell(ref)
            }

            "CreateChildObj" -> {
                val ref = context.actorOf(MinimumTestActorObj.getProps(obj), "Obj")
                sender.tell(ref)
            }

            "Get" -> {
                sender.tell(obj ?: Thing(-1))
            }

            is Thing -> {
                obj = message
            }

            else -> throw RuntimeException("Unhandled")
        }
    }

}

class PollingActor(private var count: Int, private val target: ActorRef) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(count: Int, target: ActorRef): Props {
            return createProps(PollingActor::class.java, count, target)
        }
    }

    override fun preStart() {
        target.tell(count)
        target.tell("Get")
    }

    override fun onReceive(message: Any) {
        when (message) {
            "Running" -> {
                sender.tell((count >= 0))
            }

            is Int -> {
                if (count != message) {
                    throw ActorKilledException("Counts mismatched")
                }
                --count
                if (count >= 0) {
                    sender.tell(count)
                    sender.tell("Get")
                }
            }

            else -> throw RuntimeException("Unhandled")
        }
    }

}

class TimerTestActor(var count: Int) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(count: Int): Props {
            return createProps(TimerTestActor::class.java, count)
        }
    }

    override fun preStart() {
        timers.startSingleTimer("Test", "TimerExpired", Duration.ofMillis(75L))
        timers.startTimerAtFixedDelay("Other", "OtherTimer", Duration.ofMillis(75L))
        timers.startSingleTimer("Test3", "ShouldNotFire", Duration.ofMillis(1000L))
    }

    override fun onReceive(message: Any) {
        when (message) {
            "TimerExpired" -> {
                context.log.info("One shot done")
                timers.startSingleTimer("Test", "Timer2Expired", Duration.ofMillis(75L))
            }

            "Timer2Expired" -> {
                context.log.info("One shot 2 done")
                timers.startTimerAtFixedRate("Test2", "Timer3Expired", Duration.ofMillis(100L))
                timers.cancel("Test3")
            }

            "Timer3Expired" -> {
                context.log.info("Ping $count")
                if (--count == 0) {
                    timers.cancel("Test2")
                }
            }

            "OtherTimer" -> {
                context.log.info("Other ping")
            }

            "Get" -> {
                sender.tell(count)
            }

            else -> throw RuntimeException("Unhandled")
        }
    }
}

class RecursiveActor(level: Int) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(level: Int): Props {
            return createProps(RecursiveActor::class.java, level)
        }
    }

    val child: ActorRef? = if (level > 0) {
        context.actorOf(getProps(level - 1), (level - 1).toString())
    } else null

    val child2: ActorRef? = if (level > 0) {
        context.actorOf(getProps(0), "sibling")
    } else null

    override fun onReceive(message: Any) {
        if (message is String && message.startsWith("Select:")) {
            sender.tell(context.actorSelection(message.substring("Select:".length)))
            return
        }
        sender.tell(self.path.address)
    }
}

class StopMe : RuntimeException()
class IgnoreThis : RuntimeException()
class RestartMe : RuntimeException()
class Escalate : RuntimeException()
class Escalate2 : RuntimeException()

class GrandSupervisorActor : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return createProps(GrandSupervisorActor::class.java)
        }
    }

    private var count = 0

    override fun onReceive(message: Any) {
        when (message) {
            "Ping" -> sender.tell("Pong_${count++}", self)
            "CreateChild" -> {
                val newChild = context.actorOf(SupervisorActor.getProps())
                sender.tell(newChild)
            }

            "GetChildren" -> sender.tell(context.children, self)
            else -> throw RuntimeException("Unhandled")
        }
    }

    override fun supervisorStrategy(
        context: ActorContext,
        child: ActorRef,
        cause: Throwable,
        retryCounts: Map<String, Int>
    ): SupervisorResponse {
        if (cause is Escalate2) {
            return SupervisorResponse.Escalate
        }
        return SupervisorResponse.StopChild
    }
}

class SupervisorActor : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return createProps(SupervisorActor::class.java)
        }
    }

    private var count = 0

    override fun onReceive(message: Any) {
        when (message) {
            "Ping" -> sender.tell("Pong_${count++}", self)
            "CreateChild" -> {
                val newChild = context.actorOf(ChildActor.getProps())
                sender.tell(newChild)
            }

            "GetChildren" -> sender.tell(context.children, self)
            else -> throw RuntimeException("Unhandled")
        }
    }

    override fun supervisorStrategy(
        context: ActorContext,
        child: ActorRef,
        cause: Throwable,
        retryCounts: Map<String, Int>
    ): SupervisorResponse {
        return when (cause) {
            is StopMe -> SupervisorResponse.StopChild
            is IgnoreThis -> SupervisorResponse.Ignore
            is RestartMe -> SupervisorResponse.RestartChild
            else -> SupervisorResponse.Escalate
        }
    }
}

class ChildActor : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return createProps(ChildActor::class.java)
        }
    }

    private var count = 0

    override fun onReceive(message: Any) {
        when (message) {
            "Ping" -> sender.tell("Pong_${count++}", self)
            "Stop" -> throw StopMe()
            "Ignore" -> throw IgnoreThis()
            "Restart" -> throw RestartMe()
            "Escalate" -> throw Escalate()
            "Escalate2" -> throw Escalate2()
            else -> throw RuntimeException("Unhandled")
        }
    }
}

object WatchMe

class DeadlockActor1 : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return createProps(DeadlockActor1::class.java)
        }
    }

    private val owners = mutableListOf<ActorRef>()

    override fun preStart() {
        super.preStart()
    }

    override fun onReceive(message: Any) {
        if (message is WatchMe) {
            owners += sender
        }
        for (owner in owners) {
            owner.tell("Hello")
        }
    }
}

class DeadlockActor2(private val peer: ActorRef) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(peer: ActorRef): Props {
            return createProps(DeadlockActor2::class.java, peer)
        }
    }

    private val owners = mutableListOf<ActorRef>()

    override fun preStart() {
        super.preStart()
        peer.tell(WatchMe)
    }

    override fun onReceive(message: Any) {
        if (message is WatchMe) {
            owners += sender
        }
        for (owner in owners) {
            owner.tell("Hello")
        }
    }
}


class DeadlockActor3(private val peer: ActorRef) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(peer: ActorRef): Props {
            return createProps(DeadlockActor2::class.java, peer)
        }
    }

    override fun preStart() {
        super.preStart()
        peer.tell(WatchMe)
    }

    override fun onReceive(message: Any) {
        println(message)
    }
}


class DeadlockActor4 : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return createProps(DeadlockActor4::class.java)
        }
    }

    private val childActor1: ActorRef = context.actorOf(
        DeadlockActor1.getProps(),
        "child1"
    )

    private val childActor2: ActorRef = context.actorOf(
        DeadlockActor2.getProps(childActor1),
        "child2"
    )

    private val childActor3: ActorRef = context.actorOf(
        DeadlockActor3.getProps(childActor2),
        "child3"
    )

    override fun preStart() {
        super.preStart()
    }

    override fun onReceive(message: Any) {

    }
}