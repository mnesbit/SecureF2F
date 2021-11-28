package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash
import java.security.SignatureException

class InMemoryBlockStore : BlockStore {
    private val blocks = mutableMapOf<SecureHash, Block>()
    private val missing = mutableSetOf<SecureHash>()
    private val verified = mutableMapOf<SecureHash, Boolean>()
    private val follows = mutableMapOf<SecureHash, MutableSet<SecureHash>>()

    private val _roots = mutableSetOf<SecureHash>()
    override val roots: Set<SecureHash> = _roots

    private val _heads = mutableSetOf<SecureHash>()
    override val heads: Set<SecureHash> = _heads

    override fun storeBlock(block: Block) {
        val blockId = block.id
        if (blocks.put(blockId, block) == null) {
            verified[blockId] = false
            val next = follows.getOrPut(blockId) { mutableSetOf() }
            if (next.isEmpty()) {
                _heads += blockId
            }
            missing -= blockId
            if (!block.isRoot) {
                for (predecessor in block.predecessors) {
                    if (predecessor !in blocks) {
                        missing += predecessor
                    }
                    val followSet = follows.getOrPut(predecessor) { mutableSetOf() }
                    followSet += blockId
                    _heads -= predecessor
                }
            } else {
                _roots += blockId
            }
        }
    }

    override fun getBlock(id: SecureHash): Block? = blocks[id]

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
            val currentBlock = blocks[blockId] ?: throw IllegalStateException("Corrupted block state $blockId")
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
                val currentBlock = blocks[verifyId] ?: throw IllegalStateException("Corrupted block state $verifyId")
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