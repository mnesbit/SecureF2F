package uk.co.nesbit.crypto.blockdag

import uk.co.nesbit.crypto.DigitalSignature
import uk.co.nesbit.crypto.MurmurHash3
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
    private val failures = mutableMapOf<SecureHash, Int>()
    private val pendingReplies = LinkedHashSet<SecureHash>()

    init {
        val rootBlock = Block.createRootBlock(self, signingService)
        blockStore.storeBlock(rootBlock)
    }

    companion object {
        const val MIN_FILTER_SIZE = 25
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
        val keySet = blockStore.blocks.map { ByteBuffer.wrap(it.bytes).int }.toSet()
        val newSize = if (lastMessage != null) {
            blockList.addAll(lastMessage.directRequests)
            val blocksKeys = lastMessage.invertibleBloomFilter.decode(keySet)
            if (blocksKeys.ok) {
                failures[peer] = 0
                val matchedBlocks = blockStore.blocks.filter { ByteBuffer.wrap(it.bytes).int in blocksKeys.deleted }
                blockList.addAll(matchedBlocks)
                max(
                    (4 * (blocksKeys.added.size + blocksKeys.deleted.size) + lastMessage.invertibleBloomFilter.entries.size) / 2,
                    MIN_FILTER_SIZE
                )
            } else {
                val failed = failures.getOrDefault(peer, 0) + 1
                failures[peer] = failed
                val fromPeer =
                    blockStore.blocks.mapNotNull { blockStore.getBlock(it) }.filter { it.origin == peer }
                        .map { it.id }.toSet()
                val lastHeads = lastMessage.heads.map { it.id }.toSet()
                val prevSet = blockStore.predecessorSet(fromPeer) + fromPeer +
                        blockStore.predecessorSet(lastHeads) + lastHeads
                val followSet = blockStore.blocks - prevSet
                if (failed > 3) {
                    blockList.addAll(followSet)
                }
                val expandedRequests = blockStore.predecessorSet(lastMessage.directRequests) - prevSet
                blockList.addAll(expandedRequests)
                max(
                    2 * lastMessage.invertibleBloomFilter.entries.size,
                    4 * (followSet + expandedRequests).size
                )
            }
        } else {
            failures[peer] = 0
            4 * blockStore.blocks.size
        }
        val ibf = InvertibleBloomFilter.createIBF(
            random.nextInt(),
            newSize,
            keySet
        )
        blockList.removeAll(blockStore.heads)
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
            pendingReplies += message.sender
        } catch (ex: SignatureException) {
            // do nothing
        }
    }

    private fun nextPeers(): List<SecureHash> {
        val log2 = 32 - memberService.members.size.countLeadingZeroBits()
        val peers = mutableListOf<SecureHash>()
        for (ring in 0 until (log2 / 2)) {
            val sortedPeers = memberService.members.sortedBy { x ->
                MurmurHash3.hash32(x.bytes, 0, x.bytes.size, ring)
            }
            val indexOfSelf = sortedPeers.indexOf(self)
            val peer = sortedPeers[(indexOfSelf + 1).rem(sortedPeers.size)]
            peers += peer
        }
        return peers.shuffled()
    }

    override fun getSyncMessage(): Pair<SecureHash, BlockSyncMessage> {
        val peers = nextPeers()
        pendingReplies.addAll(peers)
        val nextTarget = pendingReplies.first()
        pendingReplies.remove(nextTarget)
        return Pair(nextTarget, getSyncMessage(nextTarget))
    }
}