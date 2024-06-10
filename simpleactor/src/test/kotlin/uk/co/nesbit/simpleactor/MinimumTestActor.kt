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

class RecursiveActor(val level: Int) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(level: Int): Props {
            return createProps(RecursiveActor::class.java, level)
        }
    }

    val child: ActorRef? = if (level > 0) {
        context.actorOf(getProps(level - 1), (level - 1).toString())
    } else null

    override fun onReceive(message: Any) {
        sender.tell(self.path.address)
    }
}