package uk.co.nesbit.simpleactor.impl.messages

import uk.co.nesbit.simpleactor.ActorRef

internal class Watch(
    val watchee: ActorRef,
    val watcher: ActorRef
)

internal class Unwatch(
    val watchee: ActorRef,
    val watcher: ActorRef
)