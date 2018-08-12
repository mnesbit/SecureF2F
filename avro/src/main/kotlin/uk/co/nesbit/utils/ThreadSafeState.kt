package uk.co.nesbit.utils

import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class ThreadSafeState<out T>(val content: T, val lock: ReentrantLock = ReentrantLock()) {
    inline fun <R> locked(body: T.() -> R): R = lock.withLock { body(content) }
}