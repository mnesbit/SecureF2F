package uk.co.nesbit.simpleactor

import org.slf4j.Logger
import uk.co.nesbit.simpleactor.impl.currentActorContextInternal

abstract class AbstractActor : Actor {
    final override val context: ActorContext
        get() = currentActorContextInternal()!!

    final override val self: ActorRef
        get() = context.self

    final override val sender: ActorRef
        get() = context.sender

    final override val timers: TimerScheduler
        get() = context.timers

    final override fun log(): Logger {
        return context.log
    }

    override fun preStart() {

    }

    override fun postStop() {

    }

    override fun preRestart(reason: Throwable, message: Any) {
        context.children.forEach { child ->
            context.unwatch(child)
            context.stop(child)
        }
        postStop()
    }

    override fun postRestart(reason: Throwable?) {
        preStart()
    }

    override fun supervisorStrategy(
        context: ActorContext,
        child: ActorRef,
        cause: Throwable,
        retryCounts: Map<String, Int>
    ): SupervisorResponse {
        return when (cause) {
            is ActorInitializationException -> SupervisorResponse.StopChild
            is ActorKilledException -> SupervisorResponse.StopChild
            is Exception -> SupervisorResponse.RestartChild
            else -> SupervisorResponse.Escalate
        }
    }
}