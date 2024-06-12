package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorContext
import uk.co.nesbit.simpleactor.ActorPath
import uk.co.nesbit.simpleactor.ActorRef
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicLong

internal class ActorRefImpl(
    private val actorSystem: ActorSystemInternal,
    override val path: ActorPath,
    val uid: Long
) : ActorRef {
    companion object {
        private val actorCount = AtomicLong(0)

        fun createActorRef(actorSystem: ActorSystemInternal, path: ActorPath): ActorRefImpl {
            val uid = actorCount.getAndIncrement()
            return ActorRefImpl(actorSystem, path, uid)
        }
    }

    private var valid = true

    @Volatile
    private var target: ActorLifecycle? = null

    override fun tell(msg: Any, sender: ActorRef) {
        if (!valid) {
            actorSystem.deadLetters.tell(msg, sender)
            return
        }
        var sendTo = target
        if (sendTo == null) {
            val actor = try {
                actorSystem.resolve(this)
            } catch (ex: Exception) {
                valid = false
                actorSystem.deadLetters.tell(msg, sender)
                return
            }
            sendTo = actor
            target = actor
        }
        if (sendTo.stopped) {
            valid = false
            actorSystem.deadLetters.tell(msg, sender)
            return
        }
        sendTo.tell(msg, sender)
    }

    override fun forward(msg: Any, context: ActorContext) {
        tell(msg, context.sender)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ActorRefImpl

        if (path != other.path) return false
        if (uid != other.uid) return false

        return true
    }

    override fun hashCode(): Int {
        var result = path.hashCode()
        result = 31 * result + uid.hashCode()
        return result
    }

    override fun toString(): String = "$path:$uid"
}

internal class WaitForReplyActorRef<R>(
    private val resultClazz: Class<R>,
    private val future: CompletableFuture<R>
) : ActorRef {
    override val path: ActorPath
        get() = ActorPath("Dummy")

    override fun tell(msg: Any, sender: ActorRef) {
        if (resultClazz.isInstance(msg)) {
            @Suppress("UNCHECKED_CAST")
            future.complete(msg as R)
        } else {
            future.completeExceptionally(TypeCastException("Unable to cast ${msg.javaClass.name} to ${resultClazz.name}"))
        }
    }

    override fun forward(msg: Any, context: ActorContext) {
        future.completeExceptionally(TypeCastException("Asked to forward message rather than receive reply"))
    }

    override fun toString(): String = "WaitForReply"
}

fun <R> askInternal(target: ActorRef, msg: Any, resultClazz: Class<R>): Future<R> {
    val fut = CompletableFuture<R>()
    val replyRef = WaitForReplyActorRef(
        resultClazz,
        fut
    )
    try {
        target.tell(msg, replyRef)
    } catch (ex: Exception) {
        fut.completeExceptionally(ex)
    }
    return fut
}