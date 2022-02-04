package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash
import java.lang.Integer.max

class InMemoryBlockStore : BlockStore {
    private val _blocks = mutableMapOf<SecureHash, Block>()
    private val missing = mutableSetOf<SecureHash>()
    private val rounds = mutableMapOf<SecureHash, Int>()
    private val follows = mutableMapOf<SecureHash, MutableSet<SecureHash>>()

    private val _roots = mutableSetOf<SecureHash>()
    override val roots: Set<SecureHash> = _roots

    private val _heads = mutableSetOf<SecureHash>()
    override val heads: Set<SecureHash> get() = _heads

    override val blocks: Set<SecureHash>
        get() = _blocks.keys

    private var _delivered: List<SecureHash>? = null
    override val deliveredBlocks: List<SecureHash>
        get() {
            if (_delivered == null) {
                val blocks = rounds.toList().toMutableList()
                blocks.sortBy { it.second }
                _delivered = blocks.map { it.first }
            }
            return _delivered!!
        }

    private class ListenerRecord(val store: InMemoryBlockStore, val callback: BlockDeliveryListener) : AutoCloseable {
        override fun close() {
            store.unregisterListener(this)
        }
    }

    private val listeners = mutableListOf<ListenerRecord>()
    override fun registerDeliveryListener(listener: BlockDeliveryListener): AutoCloseable {
        val record = ListenerRecord(this, listener)
        listeners += record
        return record
    }

    private fun unregisterListener(record: ListenerRecord) {
        listeners -= record
    }

    private fun updateRoundForBlock(block: Block): Boolean {
        if (block.isRoot) {
            rounds[block.id] = 0
        } else {
            var maxRound = 0
            for (pred in block.predecessors) {
                val predRound = rounds[pred] ?: return false
                maxRound = max(predRound, maxRound)
            }
            rounds[block.id] = maxRound + 1
        }
        _delivered = null
        return true
    }

    private fun updateRounds(startBlock: Block) {
        if (rounds[startBlock.id] != null) return
        val delivered = mutableListOf<Block>()
        val queue = ArrayDeque<Block>()
        queue.addLast(startBlock)
        while (queue.isNotEmpty()) {
            val followSet = mutableSetOf<SecureHash>()
            while (queue.isNotEmpty()) {
                val block = queue.removeFirst()
                if (updateRoundForBlock(block)) {
                    delivered += block
                    _heads += block.id
                    if (!block.isRoot) {
                        for (pred in block.predecessors) {
                            _heads -= pred
                        }
                    }
                    for (follow in follows[block.id] ?: emptySet()) {
                        followSet += follow
                    }
                }
            }
            for (follow in followSet) {
                val block = _blocks[follow]
                if (block != null) {
                    queue.addLast(block)
                }
            }
        }
        for (deliveredBlock in delivered) {
            val round =
                rounds[deliveredBlock.id] ?: throw java.lang.IllegalStateException("couldn't find delivered block")
            val predecessors = if (!deliveredBlock.isRoot) {
                deliveredBlock.predecessors.map {
                    getBlock(it) ?: throw java.lang.IllegalStateException("couldn't find delivered block")
                }.toSet()
            } else {
                emptySet()
            }
            for (listenerRecord in listeners) {
                listenerRecord.callback.onDelivery(deliveredBlock, predecessors, round)
            }
        }
    }

    override fun storeBlock(block: Block): Boolean {
        val blockId = block.id
        if (_blocks.put(blockId, block) == null) {
            missing -= blockId
            if (!block.isRoot) {
                for (predecessor in block.predecessors) {
                    if (predecessor !in _blocks) {
                        missing += predecessor
                    }
                    val followSet = follows.getOrPut(predecessor) { mutableSetOf() }
                    followSet += blockId
                }
            } else {
                _roots += blockId
            }
            updateRounds(block)
            return true
        }
        return false
    }

    override fun getBlock(id: SecureHash): Block? = _blocks[id]

    override fun getRound(id: SecureHash): Int? = rounds[id]

    override fun getMissing(): Set<SecureHash> = missing

    override fun getNext(id: SecureHash): Set<SecureHash> = follows[id] ?: emptySet()

    override fun followSet(ids: Set<SecureHash>): Set<SecureHash> {
        val resultSet = mutableSetOf<SecureHash>()
        val queue = ArrayDeque<SecureHash>()
        queue.addAll(ids)
        while (queue.isNotEmpty()) {
            val expandItem = queue.removeFirst()
            val followers = follows[expandItem] ?: emptySet()
            for (next in followers) {
                if (resultSet.add(next)) {
                    queue.addLast(next)
                }
            }
        }
        return resultSet
    }

    override fun predecessorSet(ids: Set<SecureHash>): Set<SecureHash> {
        val resultSet = mutableSetOf<SecureHash>()
        val queue = ArrayDeque<SecureHash>()
        queue.addAll(ids)
        while (queue.isNotEmpty()) {
            val expandItem = queue.removeFirst()
            val expandBlock = _blocks[expandItem]
            if (expandBlock == null || expandBlock.isRoot) continue
            val predecessors = expandBlock.predecessors
            for (prev in predecessors) {
                if (resultSet.add(prev)) {
                    queue.addLast(prev)
                }
            }
        }
        return resultSet
    }
}