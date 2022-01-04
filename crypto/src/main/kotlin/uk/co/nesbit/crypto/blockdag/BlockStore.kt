package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.SecureHash

fun interface BlockDeliveryListener {
    fun onDelivery(block: Block, predecessors: Set<Block>, round: Int)
}

interface BlockStore {
    fun storeBlock(block: Block)
    fun getBlock(id: SecureHash): Block?
    fun getRound(id: SecureHash): Int?
    fun transitiveVerify(block: Block, memberService: MemberService)
    fun getMissing(): Set<SecureHash>
    fun getNext(id: SecureHash): Set<SecureHash>
    fun followSet(ids: Set<SecureHash>): Set<SecureHash>
    fun predecessorSet(ids: Set<SecureHash>): Set<SecureHash>
    val blocks: Set<SecureHash>
    val deliveredBlocks: List<SecureHash>
    val roots: Set<SecureHash>
    val heads: Set<SecureHash>

    fun registerDeliveryListener(listener: BlockDeliveryListener): AutoCloseable
}