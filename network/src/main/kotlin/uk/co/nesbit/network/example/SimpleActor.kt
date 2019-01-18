package uk.co.nesbit.network.example

import akka.actor.*
import akka.japi.pf.ReceiveBuilder
import scala.concurrent.duration.Duration

class SimpleActor : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return Props.create(SimpleActor::class.java)
        }
    }

    override fun supervisorStrategy() = AllForOneStrategy(-1, Duration.Inf()) {
        when (it) {
            is ActorInitializationException -> SupervisorStrategy.stop()
            is ActorKilledException -> SupervisorStrategy.stop()
            is DeathPactException -> SupervisorStrategy.stop()
            else -> SupervisorStrategy.restart()
        }
    }

    override fun preStart() {
        super.preStart()
        log().info("Starting Actor")
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped Actor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart Actor")
    }

    override fun createReceive() =
        ReceiveBuilder()
            .match(String::class.java) {
                log().info(it)
                context.children.forEach { child ->
                    child.tell(it, self())
                }
            }
            .build()
}

class ChildActor : AbstractLoggingActor() {
    companion object {
        @JvmStatic
        fun getProps(): Props {
            return Props.create(ChildActor::class.java)
        }
    }

    override fun preStart() {
        super.preStart()
        log().info("Starting Child Actor")
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped Child Actor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart Child Actor")
    }

    override fun createReceive() =
        ReceiveBuilder()
            .match(String::class.java, this::onMessage)
            .build()

    private fun onMessage(message: String) {
        log().info(message)
        //throw Exception("GGG")
    }
}