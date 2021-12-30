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
    private val lastMessage = mutableMapOf<SecureHash, BlockSyncMessage>()

    override fun getSyncMessage(
        peer: SecureHash,
        signingService: (SecureHash, ByteArray) -> DigitalSignature
    ): BlockSyncMessage {
        val lastMessage = lastMessage[peer]
        val heads = blockStore.heads
        val prevHeads: Set<SecureHash> = lastMessage?.heads ?: emptySet()
        val followSet = blockStore.followSet(prevHeads) + prevHeads
        val filterSet = BloomFilter.createBloomFilter(followSet.size, 0.01, random.nextInt())
        for (item in followSet) {
            filterSet.add(item.serialize())
        }
        val replyBlocks = mutableSetOf<SecureHash>()
        for (head in heads) {
            replyBlocks += head
        }
        for (request in lastMessage?.directRequests ?: emptySet()) {
            replyBlocks += request
        }
        val prevSet = blockStore.predecessorSet(prevHeads) + prevHeads
        val expectedBlocksFilter = lastMessage?.expectedBlocksFilter ?: BloomFilter.createBloomFilter(0, 0.1, 0)
        for (blockId in blockStore.blocks) {
            if (!(blockId in prevSet || expectedBlocksFilter.possiblyContains(blockId.serialize()))) {
                replyBlocks += blockId
            }
        }
        return BlockSyncMessage.createBlockSyncMessage(
            self,
            prevHeads,
            heads,
            filterSet,
            blockStore.getMissing(),
            replyBlocks.mapNotNull { blockStore.getBlock(it) },
            signingService
        )
    }

    override fun processSyncMessage(message: BlockSyncMessage) {
        try {
            message.verify(memberService)
            for (block in message.blocks) {
                blockStore.storeBlock(block)
            }
            lastMessage[message.sender] = message
        } catch (ex: SignatureException) {
            // do nothing
        }
    }
}