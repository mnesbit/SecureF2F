package uk.co.nesbit.simpleactor

import org.slf4j.Logger
import uk.co.nesbit.simpleactor.impl.currentActorContextInternal

interface ActorContext {
    val system: ActorSystem

    val log: Logger

    val self: ActorRef
    val parent: ActorRef
    val props: Props
    val timers: TimerScheduler

    val sender: ActorRef

    val children: List<ActorRef>
    fun getChild(name: String): ActorRef?
    fun actorOf(props: Props, name: String): ActorRef
    fun actorOf(props: Props): ActorRef

    fun stop(child: ActorRef)
    fun watch(other: ActorRef)
    fun unwatch(other: ActorRef)

    fun actorSelection(path: String): ActorSelection
    fun actorSelection(path: ActorPath): ActorSelection
}

fun currentActorContext(): ActorContext? {
    return currentActorContextInternal()
}