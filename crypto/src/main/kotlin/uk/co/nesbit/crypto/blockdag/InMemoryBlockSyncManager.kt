package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.BloomFilter
import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.newSecureRandom
import java.security.SignatureException

class InMemoryBlockSyncManager(
    val self: SecureHash,
    override val memberService: MemberService,
    override val blockStore: BlockStore
) : BlockSyncManager {
    private val random = newSecureRandom()
    private val oldHeads = mutableMapOf<SecureHash, Set<SecureHash>>()
    private val pendingReplies = mutableMapOf<SecureHash, Set<SecureHash>>()

    override fun getSyncMessage(
        peer: SecureHash,
        signingService: (SecureHash, ByteArray) -> DigitalSignature
    ): BlockSyncMessage {
        val heads = blockStore.heads
        val prevHeads = oldHeads[peer] ?: heads
        val followSet = blockStore.followSet(prevHeads) + prevHeads
        val filterSet = BloomFilter.createBloomFilter(followSet.size, 0.01, random.nextInt())
        for (item in followSet) {
            filterSet.add(item.serialize())
        }
        val replyBlocks = mutableSetOf<Block>()
        for (head in heads) {
            val block = blockStore.getBlock(head)
            if (block != null) {
                replyBlocks += block
            }
        }
        val pendingBlocks = pendingReplies.getOrPut(peer) { emptySet() }
        for (pending in pendingBlocks) {
            val block = blockStore.getBlock(pending)
            if (block != null) {
                replyBlocks += block
            }
        }
        return BlockSyncMessage.createBlockSyncMessage(
            self,
            prevHeads,
            heads,
            filterSet,
            blockStore.getMissing(),
            replyBlocks,
            signingService
        )
    }

    override fun processSyncMessage(message: BlockSyncMessage) {
        try {
            message.verify(memberService)
            for (block in message.blocks) {
                blockStore.storeBlock(block)
            }
            val newPending = mutableSetOf<SecureHash>()
            newPending.addAll(message.directRequests)
            for (pending in pendingReplies.getOrDefault(message.sender, emptySet())) {
                if (!message.expectedBlocksFilter.possiblyContains(pending.serialize())) {
                    newPending += pending
                }
            }
            val followSet = blockStore.followSet(message.prevHeads)
            for (follow in followSet) {
                if (!message.expectedBlocksFilter.possiblyContains(follow.serialize())) {
                    newPending += follow
                }
            }
            oldHeads[message.sender] = message.heads
            pendingReplies[message.sender] = newPending
        } catch (ex: SignatureException) {
            // do nothing
        }
    }
}