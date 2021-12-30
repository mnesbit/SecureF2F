package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash
import java.lang.Integer.max
import java.security.SignatureException

class InMemoryBlockStore : BlockStore {
    private val _blocks = mutableMapOf<SecureHash, Block>()
    private val missing = mutableSetOf<SecureHash>()
    private val verified = mutableMapOf<SecureHash, Boolean>()
    private val rounds = mutableMapOf<SecureHash, Int>()
    private val follows = mutableMapOf<SecureHash, MutableSet<SecureHash>>()

    private val _roots = mutableSetOf<SecureHash>()
    override val roots: Set<SecureHash> = _roots

    private val _heads = mutableSetOf<SecureHash>()
    override val heads: Set<SecureHash> get() = _heads

    override val blocks: Set<SecureHash>
        get() = _blocks.keys

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
        return true
    }

    private fun updateRounds(startBlock: Block) {
        if (rounds[startBlock.id] != null) return
        val queue = ArrayDeque<Block>()
        queue.addLast(startBlock)
        while (queue.isNotEmpty()) {
            val followSet = mutableSetOf<SecureHash>()
            while (queue.isNotEmpty()) {
                val block = queue.removeFirst()
                if (updateRoundForBlock(block)) {
                    _heads += block.id
                    if (!block.isRoot) {
                        for (pred in block.predecessors) {
                            _heads -= pred
                        }
                    }
                    for (follow in follows[block.id] ?: emptySet()) {
                        if (rounds[follow] == null) {
                            followSet += follow
                        }
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
    }

    override fun storeBlock(block: Block) {
        val blockId = block.id
        if (_blocks.put(blockId, block) == null) {
            verified[blockId] = false
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
        }
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

    private fun expandUnverifiedPredecessors(
        block: Block,
        verifyList: MutableList<SecureHash>,
        verifySet: MutableSet<SecureHash>
    ) {
        if (block.isRoot) return
        for (predecessor in block.predecessors) {
            if (predecessor !in verifySet) {
                verifySet += predecessor
                val verifyState = verified[predecessor]
                if (verifyState == null) {
                    throw SignatureException("Missing transitive dependency $predecessor")
                } else if (verifyState == false) {
                    verifyList += predecessor
                }
            }
        }
    }

    override fun transitiveVerify(block: Block, memberService: MemberService) {
        block.verify(memberService)
        val verifySet = mutableSetOf<SecureHash>()
        val unverifiedList = mutableListOf<SecureHash>()
        expandUnverifiedPredecessors(block, unverifiedList, verifySet)
        var index = 0
        while (index < unverifiedList.size) {
            val blockId = unverifiedList[index]
            val currentBlock = _blocks[blockId] ?: throw IllegalStateException("Corrupted block state $blockId")
            expandUnverifiedPredecessors(currentBlock, unverifiedList, verifySet)
            ++index
        }
        val reversed = unverifiedList.asReversed()
        var progress = true
        while (progress) {
            progress = false
            val itr = reversed.iterator()
            while (itr.hasNext()) {
                val verifyId = itr.next()
                val currentBlock = _blocks[verifyId] ?: throw IllegalStateException("Corrupted block state $verifyId")
                val predecessorsDone = currentBlock.isRoot || currentBlock.predecessors.all { verified[it] == true }
                if (predecessorsDone) {
                    currentBlock.verify(memberService)
                    verified[verifyId] = true
                    progress = true
                    itr.remove()
                }
            }
        }
        if (reversed.isNotEmpty()) throw SignatureException("Unable to verify all transitive blocks")
    }

}