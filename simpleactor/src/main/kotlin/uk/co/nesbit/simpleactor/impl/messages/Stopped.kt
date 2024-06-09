package uk.co.nesbit.simpleactor.impl.messages

import uk.co.nesbit.simpleactor.ActorPath

internal class Stopped(val oldPath: ActorPath, val oldUid: Long)

internal class ChildStopped(val oldPath: ActorPath, val oldUid: Long)