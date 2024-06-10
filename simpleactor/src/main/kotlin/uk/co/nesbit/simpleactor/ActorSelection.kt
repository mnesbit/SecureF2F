package uk.co.nesbit.simpleactor

interface ActorSelection {
    val pathString: String
    fun resolve(): List<ActorRef>
    fun tell(msg: Any, sender: ActorRef = currentActorContext()?.self ?: Actor.NoSender)
    fun forward(msg: Any, context: ActorContext = currentActorContext()!!)
}