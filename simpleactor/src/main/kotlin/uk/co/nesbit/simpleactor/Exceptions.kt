package uk.co.nesbit.simpleactor

open class SimpleActorException(msg: String, cause: Throwable?) : RuntimeException(msg, cause) {
    constructor(msg: String) : this(msg, null)
}

class ActorInitializationException(msg: String, cause: Throwable?) : SimpleActorException(msg, cause) {
    constructor(msg: String) : this(msg, null)
}

class ActorKilledException(msg: String, cause: Throwable?) : SimpleActorException(msg, cause) {
    constructor(msg: String) : this(msg, null)
}

class UnhandledMessage(msg: String, cause: Throwable?) : SimpleActorException(msg, cause) {
    constructor(msg: String) : this(msg, null)
}
