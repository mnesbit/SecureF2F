package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorRef
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.atomic.AtomicBoolean

internal class MailboxImpl(
    private val executor: ExecutorService,
    private val handler: MailHandler
) : MailBox {
    companion object {
        const val BATCH_SIZE_US = 1000L

        @JvmStatic
        private val onMailThread = ThreadLocal.withInitial { false }
    }

    @Volatile
    private var paused = true
    private val queue = ConcurrentLinkedDeque<MessageEntry>()
    private val pending = AtomicBoolean(false)

    override fun tell(msg: Any, sender: ActorRef) {
        queue.offer(MessageEntry(msg, sender))
        tryScheduleReceive()
    }

    override fun tellPriority(msg: Any, sender: ActorRef) {
        queue.offerFirst(MessageEntry(msg, sender))
        tryScheduleReceive()
    }

    override fun pause() {
        if (!paused) {
            runExclusive {
                paused = true
            }
        }
    }

    override fun resume() {
        if (paused) {
            paused = false
            tryScheduleReceive()
        }
    }

    override fun clear(): List<MessageEntry> {
        val undelivered = mutableListOf<MessageEntry>()
        runExclusive {
            while (true) {
                val head = queue.poll() ?: break
                undelivered += head
            }
        }
        return undelivered
    }

    private fun tryScheduleReceive() {
        if (paused) {
            return
        }
        val alreadyPending = pending.getAndSet(true)
        if (!alreadyPending) {
            executor.execute {
                processMessages()
            }
        }
    }

    override fun inHandler(): Boolean {
        return onMailThread.get()
    }

    private fun runExclusive(block: () -> Unit) {
        if (inHandler()) {
            block()
            return
        }
        while (true) {
            val alreadyPending = pending.getAndSet(true)
            if (!alreadyPending) {
                executor.submit {
                    try {
                        block()
                    } finally {
                        pending.set(false)
                    }
                }.get()
                break
            }
        }
    }

    private fun processMessages() {
        val startTime = System.nanoTime()
        val prevValue = onMailThread.get()
        onMailThread.set(true)
        try {
            do {
                val messageEntry = queue.poll() ?: break
                handler.onReceive(messageEntry.msg, messageEntry.sender)
            } while ((System.nanoTime() - startTime) / 1000L < BATCH_SIZE_US)
        } finally {
            onMailThread.set(prevValue)
            pending.set(false)
            if (!queue.isEmpty()) {
                tryScheduleReceive()
            }
        }
    }
}