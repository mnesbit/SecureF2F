package uk.co.nesbit.simpleactor.impl

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater
import kotlin.concurrent.Volatile

//Lock free Multi-producer Single-Consumer queue from https://psy-lob-saw.blogspot.com/2015/04/porting-dvyukov-mpsc.html
// originally based upon https://www.1024cores.net/home/lock-free-algorithms/queues/intrusive-mpsc-node-based-queue
internal class MPSCQueue<T> {
    companion object {
        @JvmStatic
        val headUpdater: AtomicReferenceFieldUpdater<MPSCQueue<*>, Node<*>> =
            AtomicReferenceFieldUpdater.newUpdater(MPSCQueue::class.java, Node::class.java, "head")
    }

    internal class Node<T> {
        @JvmField
        var value: T? = null

        // C 'volatile' is not the same as Java 'volatile', but in this case they happen to
        // apply to the same fields.
        @Volatile
        @JvmField
        var next: Node<T>? = null
    }

    @Volatile
    @JvmField
    var head: Node<T>

    @JvmField
    var tail: Node<T>

    init {
        tail = Node()
        head = tail
    }

    @Suppress("UNCHECKED_CAST")
    fun offer(value: T): Boolean {
        val newNode = Node<T>()
        newNode.value = value
        val prev: Node<T> = headUpdater.getAndSet(this, newNode) as Node<T>
        prev.next = newNode
        return true
    }

    fun isEmpty(): Boolean {
        return head == tail
    }

    fun isNotEmpty(): Boolean {
        return head != tail
    }

    fun poll(): T? {
        val tailNode = tail
        var next = tailNode.next
        if (next != null) {
            return consumeNode(next)
        } else if (tailNode !== head) {
            @Suppress("ControlFlowWithEmptyBody")
            while ((tailNode.next.also { next = it }) == null);
            return consumeNode(next!!)
        }
        return null
    }

    fun peek(): T? {
        val tailNode: Node<T> = tail
        var next = tailNode.next
        if (next != null) {
            return next.value
        } else if (tailNode !== head) {
            @Suppress("ControlFlowWithEmptyBody")
            while ((tailNode.next.also { next = it }) == null);
            return next!!.value
        }
        return null
    }

    private fun consumeNode(next: Node<T>): T? {
        val value = next.value
        next.value = null
        tail = next
        return value
    }
}