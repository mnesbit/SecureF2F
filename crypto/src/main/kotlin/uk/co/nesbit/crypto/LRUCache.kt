package uk.co.nesbit.crypto

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

class LRUCache<K, V>(private val capacity: Int) {
    private val map = ConcurrentHashMap<K, V>()
    private val queue = ConcurrentLinkedQueue<K>()

    operator fun get(key: K): V? {
        val entry = map[key]
        if (entry != null) {
            queue.add(key)
            queue.remove(key)
        }
        return entry
    }

    operator fun set(key: K, value: V) {
        if (map.containsKey(key)) {
            queue.remove(key)
        }

        if (queue.size >= capacity) {
            val expiredKey = queue.poll()

            if (expiredKey != null) {
                map.remove(expiredKey)
            }
        }

        queue.add(key)
        map[key] = value
    }
}