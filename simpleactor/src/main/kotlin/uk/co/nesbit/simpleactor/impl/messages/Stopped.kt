package uk.co.nesbit.simpleactor.impl.messages

import uk.co.nesbit.simpleactor.ActorPath
import uk.co.nesbit.simpleactor.ActorRef

internal class Stopped(val oldPath: ActorPath, val oldUid: Long)

internal class ChildStopped(val oldPath: ActorPath, val oldUid: Long, val watchList: List<ActorRef>)