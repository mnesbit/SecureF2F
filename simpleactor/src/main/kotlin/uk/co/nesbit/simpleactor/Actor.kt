package uk.co.nesbit.simpleactor

import org.slf4j.Logger

interface Actor {
    companion object {
        val NoSender: ActorRef = object : ActorRef {
            override val path: ActorPath
                get() {
                    throw UnhandledMessage("Cannot take path of NoSender")
                }

            override fun tell(msg: Any, sender: ActorRef) {
            }

            override fun forward(msg: Any, context: ActorContext) {
            }

            override fun toString(): String = "NoSender"
        }
    }

    val context: ActorContext
    val self: ActorRef
    val sender: ActorRef
    val timers: TimerScheduler

    fun log(): Logger

    fun preStart()
    fun postStop()
    fun preRestart(reason: Throwable, message: Any)
    fun postRestart(reason: Throwable?)
    fun supervisorStrategy(
        context: ActorContext,
        child: ActorRef,
        cause: Throwable,
        retryCounts: Map<String, Int>
    ): SupervisorResponse

    fun onReceive(message: Any)
}