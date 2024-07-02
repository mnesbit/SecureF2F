package uk.co.nesbit.simpleactor.impl

import org.jctools.queues.MpscLinkedQueue
import uk.co.nesbit.simpleactor.ActorRef
import java.util.concurrent.ExecutorService
import java.util.concurrent.atomic.AtomicBoolean

internal class MailboxImpl(
    private val executor: ExecutorService,
    private val batchSizeUS: Long,
    private val handler: MailHandler
) : MailBox {
    @Volatile
    private var paused = true
    private val priorityQueue = MpscLinkedQueue<MessageEntry>()
    private val queue = MpscLinkedQueue<MessageEntry>()
    private val pending = AtomicBoolean(false)

    @Volatile
    private var mailThread = -1L

    override fun tell(msg: Any, sender: ActorRef) {
        queue.offer(MessageEntry(msg, sender))
        tryScheduleReceive()
    }

    override fun tellPriority(msg: Any, sender: ActorRef) {
        priorityQueue.offer(MessageEntry(msg, sender))
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

    private fun inHandler(): Boolean {
        return (mailThread == Thread.currentThread().threadId())
    }

    override fun <R> runExclusive(block: () -> R): R {
        if (inHandler()) { // avoid blocking
            return block()
        }
        while (true) {
            val alreadyPending = pending.getAndSet(true)
            if (!alreadyPending) {
                val result = try {
                    block()
                } finally {
                    pending.set(false)
                }
                if (queue.isNotEmpty() || priorityQueue.isNotEmpty()) {
                    tryScheduleReceive()
                }
                return result
            }
        }
    }

    private fun processMessages() {
        val startTime = System.nanoTime()
        mailThread = Thread.currentThread().threadId()
        try {
            do {
                val priorityMessage = priorityQueue.poll()
                if (priorityMessage != null) {
                    handler.onReceive(priorityMessage.msg, priorityMessage.sender)
                } else {
                    val messageEntry = queue.poll() ?: break
                    handler.onReceive(messageEntry.msg, messageEntry.sender)
                }
            } while ((System.nanoTime() - startTime) / 1000L < batchSizeUS)
        } finally {
            mailThread = -1L
            pending.set(false)
            if (queue.isNotEmpty() || priorityQueue.isNotEmpty()) {
                tryScheduleReceive()
            }
        }
    }
}