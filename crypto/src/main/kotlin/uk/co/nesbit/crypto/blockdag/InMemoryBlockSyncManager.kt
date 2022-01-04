package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.setsync.InvertibleBloomFilter
import java.nio.ByteBuffer
import java.security.SignatureException
import kotlin.math.max

class InMemoryBlockSyncManager(
    val self: SecureHash,
    override val memberService: MemberService,
    override val blockStore: BlockStore,
    override val signingService: (SecureHash, ByteArray) -> DigitalSignature
) : BlockSyncManager {
    private val random = newSecureRandom()
    private val lastMessage = mutableMapOf<SecureHash, BlockSyncMessage>()

    init {
        val rootBlock = Block.createRootBlock(self, signingService)
        blockStore.storeBlock(rootBlock)
    }

    companion object {
        val MIN_FILTER_SIZE = 25
    }

    override fun createBlock(
        data: ByteArray
    ): Block {
        val newBlock = Block.createBlock(
            self,
            blockStore.heads.toList(),
            data,
            signingService
        )
        blockStore.storeBlock(newBlock)
        return newBlock
    }

    override fun getSyncMessage(
        peer: SecureHash
    ): BlockSyncMessage {
        val lastMessage = lastMessage[peer]
        val blockList = mutableSetOf<SecureHash>()
        val keySet = blockStore.deliveredBlocks.map { ByteBuffer.wrap(it.bytes).int }.toSet()
        val newSize = if (lastMessage != null) {
            blockList.addAll(lastMessage.directRequests)
            val blocksKeys = lastMessage.invertibleBloomFilter.decode(keySet)
            if (blocksKeys.ok) {
                val matchedBlocks = blockStore.blocks.filter { ByteBuffer.wrap(it.bytes).int in blocksKeys.deleted }
                blockList.addAll(matchedBlocks)
                max(4 * blocksKeys.added.size + (lastMessage.invertibleBloomFilter.entries.size / 2), MIN_FILTER_SIZE)
            } else {
                val fromPeer =
                    blockStore.deliveredBlocks.mapNotNull { blockStore.getBlock(it) }.filter { it.origin == peer }
                        .map { it.id }.toSet()
                val prevSet = blockStore.predecessorSet(fromPeer) + fromPeer
                val followSet = blockStore.deliveredBlocks - prevSet
                blockList.addAll(followSet)
                val expandedRequests = blockStore.predecessorSet(lastMessage.directRequests) - prevSet
                blockList.addAll(expandedRequests)
                max(2 * lastMessage.invertibleBloomFilter.entries.size, 4 * blockList.size)
            }
        } else {
            MIN_FILTER_SIZE
        }
        val ibf = InvertibleBloomFilter.createIBF(
            random.nextInt(),
            newSize,
            keySet
        )
        return BlockSyncMessage.createBlockSyncMessage(
            self,
            ibf,
            blockStore.heads.mapNotNull { blockStore.getBlock(it) },
            blockStore.getMissing(),
            blockList.mapNotNull { blockStore.getBlock(it) },
            signingService
        )
    }

    override fun processSyncMessage(message: BlockSyncMessage) {
        try {
            message.verify(memberService)
            for (head in message.heads) {
                blockStore.storeBlock(head)
            }
            for (block in message.blocks) {
                blockStore.storeBlock(block)
            }
            lastMessage[message.sender] = message
        } catch (ex: SignatureException) {
            // do nothing
        }
    }
}