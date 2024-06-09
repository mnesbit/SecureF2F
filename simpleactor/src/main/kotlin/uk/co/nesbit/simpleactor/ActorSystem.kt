package uk.co.nesbit.simpleactor

import com.typesafe.config.Config
import uk.co.nesbit.simpleactor.impl.ActorSystemImpl

interface ActorSystem {
    companion object {
        fun create(name: String, config: Config): ActorSystem = ActorSystemImpl(name, config)
    }

    val name: String
    val config: Config

    fun actorOf(props: Props, name: String): ActorRef
    fun actorOf(props: Props): ActorRef

    fun stop(actor: ActorRef)
    fun stop()
}