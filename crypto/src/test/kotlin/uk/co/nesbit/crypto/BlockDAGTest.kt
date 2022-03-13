package uk.co.nesbit.crypto

import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.blockdag.*
import uk.co.nesbit.crypto.setsync.InvertibleBloomFilter
import java.lang.Integer.min
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.PublicKey
import kotlin.math.max
import kotlin.math.sqrt
import kotlin.random.Random
import kotlin.test.assertEquals

class BlockDAGTest {
    @Test
    fun `Round trip serialize block`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = keyPair.public.id
        val memberService = object : MemberService {
            override val members: Set<SecureHash>
                get() = setOf(keyId)

            override fun getMemberKey(id: SecureHash): PublicKey? {
                assertEquals(keyId, id)
                return keyPair.public
            }
        }
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x)
        }
        val payload = "01233456789".toByteArray(Charsets.UTF_8)
        val predecessors = (0..3).map { SecureHash.secureHash(it.toString()) }
        val block = Block.createBlock(
            keyId,
            predecessors,
            payload,
            signingService
        )
        block.verify(memberService)
        val serialized = block.serialize()
        val deserialized = Block.deserialize(serialized)
        assertEquals(block, deserialized)
        deserialized.verify(memberService)
        assertEquals(block.id, deserialized.id)
    }

    @Test
    fun `test block store heads logic`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = keyPair.public.id
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x)
        }
        val random = Random.Default
        val blockIds = mutableListOf<SecureHash>()
        val blocks = mutableListOf<Block>()
        val rootBlock = Block.createRootBlock(keyId, signingService)
        blockIds += rootBlock.id
        blocks += rootBlock
        val heads = mutableSetOf<SecureHash>()
        for (i in 0 until 500) {
            val inputs = 1 + min(random.nextInt(10), blocks.size - 1)
            val inputIds = mutableSetOf<SecureHash>()
            for (j in 0 until inputs) {
                val pred = blockIds[random.nextInt(blockIds.size)]
                inputIds += pred
                heads -= pred
            }
            val newBlock = Block.createBlock(keyId, inputIds.toList(), i.toByteArray(), signingService)
            blockIds += newBlock.id
            blocks += newBlock
            heads += newBlock.id
        }
        val shuffled = blocks.shuffled()
        val blockStore: BlockStore = InMemoryBlockStore()
        for (block in shuffled) {
            blockStore.storeBlock(block)
        }
        assertEquals(heads, blockStore.heads)
        assertEquals(emptySet(), blockStore.followSet(heads))
        assertEquals(blockIds.toSet().minus(rootBlock.id), blockStore.followSet(setOf(rootBlock.id)))
        assertEquals(emptySet(), blockStore.followSet(emptySet()))
    }

    @Test
    fun `BlockStore predecessor test`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = keyPair.public.id
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x)
        }
        val blocks = mutableMapOf<Int, Block>()
        val blockStore: BlockStore = InMemoryBlockStore()
        val rootBlock = Block.createRootBlock(keyId, signingService)
        blocks[-1] = rootBlock
        blockStore.storeBlock(rootBlock)
        var prevBlock = rootBlock
        for (i in 0 until 10) {
            val newBlock = Block.createBlock(keyId, listOf(prevBlock.id), i.toString().toByteArray(), signingService)
            blockStore.storeBlock(newBlock)
            blocks[i] = newBlock
            prevBlock = newBlock
        }
        val midBlock = prevBlock
        for (i in 10 until 20) {
            val newBlock = Block.createBlock(keyId, listOf(prevBlock.id), i.toString().toByteArray(), signingService)
            blockStore.storeBlock(newBlock)
            blocks[i] = newBlock
            prevBlock = newBlock
        }
        prevBlock = midBlock
        for (i in 20 until 30) {
            val newBlock = Block.createBlock(keyId, listOf(prevBlock.id), i.toString().toByteArray(), signingService)
            blockStore.storeBlock(newBlock)
            blocks[i] = newBlock
            prevBlock = newBlock
        }
        for (i in 0 until 30) {
            val pred = blockStore.predecessorSet(setOf(blocks[i]!!.id))
            if (i < 20) {
                val expected = (-1 until i).map { blocks[it]!!.id }.toSet()
                assertEquals(expected, pred)
            } else {
                val expectedStart = (-1 until 10).map { blocks[it]!!.id }.toSet()
                val expected = (20 until i).map { blocks[it]!!.id }.toSet()
                assertEquals(expectedStart + expected, pred)
            }
        }
        assertEquals(emptySet(), blockStore.predecessorSet(emptySet()))
    }

    @Test
    fun `BlockSyncMessage serialization test`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = keyPair.public.id
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x)
        }
        val memberService = object : MemberService {
            override val members: Set<SecureHash>
                get() = setOf(keyId)

            override fun getMemberKey(id: SecureHash): PublicKey? {
                assertEquals(keyId, id)
                return keyPair.public
            }
        }
        val random = Random.Default
        val blockIds = mutableListOf<SecureHash>()
        val blocks = mutableListOf<Block>()
        val rootBlock = Block.createRootBlock(keyId, signingService)
        blockIds += rootBlock.id
        blocks += rootBlock
        val heads = mutableSetOf<SecureHash>()
        for (i in 0 until 50) {
            val inputs = 1 + min(random.nextInt(5), blocks.size - 1)
            val inputIds = mutableSetOf<SecureHash>()
            for (j in 0 until inputs) {
                val pred = blockIds[random.nextInt(blockIds.size)]
                inputIds += pred
                heads -= pred
            }
            val newBlock = Block.createBlock(keyId, inputIds.toList(), i.toByteArray(), signingService)
            blockIds += newBlock.id
            blocks += newBlock
            heads += newBlock.id
        }
        val blockStore: BlockStore = InMemoryBlockStore()
        for (block in blocks) {
            blockStore.storeBlock(block)
        }
        val followSet = blockStore.followSet(blockStore.roots) + rootBlock.id
        val filterSet = BloomFilter.createBloomFilter(followSet.size, 0.01, 123456)
        followSet.forEach { filterSet.add(it.serialize()) }
        val keySet = followSet.map { ByteBuffer.wrap(it.bytes).int }.toSet()
        val invertibleBloomFilter = InvertibleBloomFilter.createIBF(999, followSet.size / 2, keySet)
        val syncMessage = BlockSyncMessage.createBlockSyncMessage(
            keyId,
            invertibleBloomFilter,
            blockStore.heads.mapNotNull { blockStore.getBlock(it) },
            listOf(SecureHash.secureHash("1"), SecureHash.secureHash("2")),
            blocks.takeLast(10),
            signingService
        )
        syncMessage.verify(memberService)
        val serialized = syncMessage.serialize()
        val deserialized = BlockSyncMessage.deserialize(serialized)
        assertEquals(syncMessage, deserialized)
        deserialized.verify(memberService)
    }

    @ParameterizedTest
    @CsvSource("10,1000", "100,200")
    fun `BlockSyncManager test`(members: Int, runLength: Int) {
        val random = newSecureRandom()
        val keys = (0 until members).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(it.public.id, it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { it.public.id }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes)
        }

        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore(),
                signingService
            )
        }

        var sentSize = 0L
        var msgSent = 0L
        for (i in 0 until runLength) {
            val member = network[i.rem(network.size)]
            member.createBlock(i.toString().toByteArray(Charsets.UTF_8))
            val peer = network[random.nextInt(network.size)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self)
                val msgSize = syncMessage.serialize().size
                sentSize += msgSize
                ++msgSent
                println("blocks sent ${syncMessage.blocks.size} $msgSize ${member.blockStore.blocks.size} ${peer.blockStore.blocks.size} diff ${(member.blockStore.blocks - peer.blockStore.blocks).size} ${(peer.blockStore.blocks - member.blockStore.blocks).size}")
                peer.processSyncMessage(syncMessage)
            }
        }
        println("average msg size = ${sentSize / msgSent}")
        var syncSize = 0
        var syncCount = 0
        var worstRound = 0
        var totalBlocks = 0
        var excessBlockCount = 0
        for (memberIndex1 in 0 until network.size - 1) {
            val member1 = network[memberIndex1]
            for (memberIndex2 in memberIndex1 until network.size) {
                val member2 = network[memberIndex2]
                var round = 0
                while (member1.blockStore.deliveredBlocks.toSet() != member2.blockStore.deliveredBlocks.toSet()) {
                    val (membera, memberb) = if (round and 1 == 0) {
                        Pair(member1, member2)
                    } else {
                        Pair(member2, member1)
                    }
                    val sync1 = membera.getSyncMessage(memberb.self)
                    val sync1Size = sync1.serialize().size
                    syncSize += sync1Size
                    ++syncCount
                    totalBlocks += sync1.blocks.size
                    val excess = (memberb.blockStore.blocks intersect (sync1.blocks.map { it.id }.toSet())).size
                    excessBlockCount += excess
                    println("$memberIndex1->$memberIndex2 sync sent$round ${sync1.blocks.size} $sync1Size ${membera.blockStore.blocks.size} ${memberb.blockStore.blocks.size} diff ${(membera.blockStore.blocks - memberb.blockStore.blocks).size} ${(memberb.blockStore.blocks - membera.blockStore.blocks).size} excess $excess")
                    memberb.processSyncMessage(sync1)
                    round++
                    worstRound = max(round, worstRound)
                }
            }
        }
        println("bytes to sync = $syncSize average ${syncSize / syncCount} worst round $worstRound excess block $excessBlockCount of $totalBlocks")
        for (member in network) {
            assertEquals(network.size, member.blockStore.roots.size)
            assertEquals(true, member.blockStore.getMissing().isEmpty())
            assertEquals(
                network[0].blockStore.blocks,
                member.blockStore.blocks
            )
        }
        assertEquals(true, worstRound <= 4, "sync too slow took $worstRound rounds")

    }

    @Test
    fun `BlockSyncManager test merging partitioned chains`() {
        val random = newSecureRandom()
        val keys = (0..9).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(it.public.id, it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { it.public.id }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes)
        }

        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore(),
                signingService
            )
        }

        val halfSize = network.size / 2
        for (i in 0 until 500) {
            val member = network[i.rem(halfSize)]
            member.createBlock(i.toString().toByteArray(Charsets.UTF_8))
            val peer = network[random.nextInt(halfSize)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self)
                peer.processSyncMessage(syncMessage)
            }
        }
        for (i in 0 until 500) {
            val member = network[halfSize + i.rem(network.size - halfSize)]
            member.createBlock(i.toString().toByteArray(Charsets.UTF_8))
            val peer = network[halfSize + random.nextInt(network.size - halfSize)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self)
                peer.processSyncMessage(syncMessage)
            }
        }
        var syncSize = 0L
        var syncCount = 0L
        var worstRound = 0
        var totalBlocks = 0
        var excessBlockCount = 0
        for (memberIndex1 in 0 until network.size - 1) {
            val member1 = network[memberIndex1]
            for (memberIndex2 in memberIndex1 until network.size) {
                val member2 = network[memberIndex2]
                var round = 0
                while (member1.blockStore.deliveredBlocks.toSet() != member2.blockStore.deliveredBlocks.toSet()) {
                    val (membera, memberb) = if (round and 1 == 0) {
                        Pair(member1, member2)
                    } else {
                        Pair(member2, member1)
                    }
                    val sync1 = membera.getSyncMessage(memberb.self)
                    val sync1Size = sync1.serialize().size
                    syncSize += sync1Size
                    ++syncCount
                    totalBlocks += sync1.blocks.size
                    val excess = (memberb.blockStore.blocks intersect (sync1.blocks.map { it.id }.toSet())).size
                    excessBlockCount += excess
                    println("sync sent$round ${sync1.blocks.size} $sync1Size ${membera.blockStore.blocks.size} ${memberb.blockStore.blocks.size} diff ${(membera.blockStore.blocks - memberb.blockStore.blocks).size} ${(memberb.blockStore.blocks - membera.blockStore.blocks).size} excess $excess")
                    memberb.processSyncMessage(sync1)
                    round++
                    worstRound = max(round, worstRound)
                }
            }
        }
        println("bytes to sync = $syncSize average ${syncSize / syncCount} worst round $worstRound excess block $excessBlockCount of $totalBlocks")
        for (member in network) {
            assertEquals(network.size, member.blockStore.roots.size)
            assertEquals(true, member.blockStore.getMissing().isEmpty())
            assertEquals(
                network[0].blockStore.blocks,
                member.blockStore.blocks
            )
        }
        assertEquals(true, worstRound <= 4, "sync too slow took $worstRound rounds")

    }

    @Test
    fun `BlockSyncManager sync with lost packets`() {
        val random = newSecureRandom()
        val keys = (0 until 10).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(it.public.id, it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { it.public.id }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes)
        }
        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore(),
                signingService
            )
        }

        var sentSize = 0L
        var msgSent = 0L
        for (i in 0 until 2000) {
            val member = network[i.rem(network.size)]
            member.createBlock(i.toString().toByteArray(Charsets.UTF_8))
            if (random.nextDouble() < 0.9) continue
            val peer = network[random.nextInt(network.size)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self)
                val msgSize = syncMessage.serialize().size
                sentSize += msgSize
                ++msgSent
                println("blocks sent ${syncMessage.blocks.size} $msgSize ${member.blockStore.blocks.size} ${peer.blockStore.blocks.size} diff ${(member.blockStore.blocks - peer.blockStore.blocks).size} ${(peer.blockStore.blocks - member.blockStore.blocks).size}")
                peer.processSyncMessage(syncMessage)
            }
        }
        println("average msg size = ${sentSize / msgSent}")
        var syncSize = 0L
        var syncCount = 0L
        var worstRound = 0
        var totalBlocks = 0
        var excessBlockCount = 0
        for (memberIndex1 in 0 until network.size - 1) {
            val member1 = network[memberIndex1]
            for (memberIndex2 in memberIndex1 until network.size) {
                val member2 = network[memberIndex2]
                var round = 0
                while (member1.blockStore.deliveredBlocks.toSet() != member2.blockStore.deliveredBlocks.toSet()) {
                    if (random.nextDouble() < 0.5) {
                        continue
                    }
                    val (membera, memberb) = if (round and 1 == 0) {
                        Pair(member1, member2)
                    } else {
                        Pair(member2, member1)
                    }
                    val sync1 = membera.getSyncMessage(memberb.self)
                    val sync1Size = sync1.serialize().size
                    syncSize += sync1Size
                    ++syncCount
                    totalBlocks += sync1.blocks.size
                    val excess = (memberb.blockStore.blocks intersect (sync1.blocks.map { it.id }.toSet())).size
                    excessBlockCount += excess
                    println("$memberIndex1->$memberIndex2 sync sent$round ${sync1.blocks.size} $sync1Size ${membera.blockStore.blocks.size} ${memberb.blockStore.blocks.size} diff ${(membera.blockStore.blocks - memberb.blockStore.blocks).size} ${(memberb.blockStore.blocks - membera.blockStore.blocks).size} excess $excess")
                    memberb.processSyncMessage(sync1)
                    round++
                    worstRound = max(round, worstRound)
                }
            }
        }
        println("bytes to sync = $syncSize average ${syncSize / syncCount} worst round $worstRound excess block $excessBlockCount of $totalBlocks")
        for (member in network) {
            assertEquals(network.size, member.blockStore.roots.size)
            assertEquals(true, member.blockStore.getMissing().isEmpty())
            assertEquals(
                network[0].blockStore.blocks,
                member.blockStore.blocks
            )
        }
        assertEquals(true, worstRound <= 4, "sync too slow took $worstRound rounds")
    }

    @Test
    fun `BlockSyncManager sync with long local chains`() {
        val random = newSecureRandom()
        val keys = (0 until 10).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(it.public.id, it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { it.public.id }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes)
        }
        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore(),
                signingService
            )
        }

        var sentSize = 0L
        var msgSent = 0L
        var msgCreated = 0
        for (i in 0 until 100) {
            for (j in 0 until 10 * network.size) {
                val member = network[j.rem(network.size)]
                member.createBlock(msgCreated.toString().toByteArray(Charsets.UTF_8))
                ++msgCreated
            }
            val sourceMember = network[i.rem(network.size)]
            val peer = network[random.nextInt(network.size)]
            if (sourceMember != peer) {
                val syncMessage = sourceMember.getSyncMessage(peer.self)
                val msgSize = syncMessage.serialize().size
                sentSize += msgSize
                ++msgSent
                println("blocks sent ${syncMessage.blocks.size} $msgSize ${sourceMember.blockStore.blocks.size} ${peer.blockStore.blocks.size} diff ${(sourceMember.blockStore.blocks - peer.blockStore.blocks).size} ${(peer.blockStore.blocks - sourceMember.blockStore.blocks).size}")
                peer.processSyncMessage(syncMessage)
            }
        }
        println("average msg size = ${sentSize / msgSent}")
        var syncSize = 0L
        var syncCount = 0L
        var worstRound = 0
        var totalBlocks = 0
        var excessBlockCount = 0
        for (memberIndex1 in 0 until network.size - 1) {
            val member1 = network[memberIndex1]
            for (memberIndex2 in memberIndex1 until network.size) {
                val member2 = network[memberIndex2]
                var round = 0
                while (member1.blockStore.deliveredBlocks.toSet() != member2.blockStore.deliveredBlocks.toSet()) {
                    val (membera, memberb) = if (round and 1 == 0) {
                        Pair(member1, member2)
                    } else {
                        Pair(member2, member1)
                    }
                    val sync1 = membera.getSyncMessage(memberb.self)
                    val sync1Size = sync1.serialize().size
                    syncSize += sync1Size
                    ++syncCount
                    totalBlocks += sync1.blocks.size
                    val excess = (memberb.blockStore.blocks intersect (sync1.blocks.map { it.id }.toSet())).size
                    excessBlockCount += excess
                    println("$memberIndex1->$memberIndex2 sync sent$round ${sync1.blocks.size} $sync1Size ${membera.blockStore.blocks.size} ${memberb.blockStore.blocks.size} diff ${(membera.blockStore.blocks - memberb.blockStore.blocks).size} ${(memberb.blockStore.blocks - membera.blockStore.blocks).size} excess $excess")
                    memberb.processSyncMessage(sync1)
                    round++
                    worstRound = max(round, worstRound)
                }
            }
        }
        println("bytes to sync = $syncSize average ${syncSize / syncCount} worst round $worstRound excess block $excessBlockCount of $totalBlocks")
        for (member in network) {
            assertEquals(network.size, member.blockStore.roots.size)
            assertEquals(true, member.blockStore.getMissing().isEmpty())
            assertEquals(
                network[0].blockStore.blocks,
                member.blockStore.blocks
            )
        }
        assertEquals(true, worstRound <= 4, "sync too slow took $worstRound rounds")
    }

    @ParameterizedTest
    @CsvSource("100,20")
    fun `BlockSyncManager sync with built in peer selection`(networkSize: Int, rounds: Int) {
        val random = newSecureRandom()
        val keys = (0 until networkSize).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(it.public.id, it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { it.public.id }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes)
        }

        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore(),
                signingService
            )
        }
        val allBlocks = mutableSetOf<SecureHash>()
        var sentSize = 0L
        var msgSent = 0L
        var totalExcess = 0L
        var totalBlocks = 0L
        for (i in 0 until rounds) {
            val shuffledNetwork = network.shuffled()
            for (sourceMember in shuffledNetwork) {
                val selfIndex = network.indexOf(sourceMember)
                val block = sourceMember.createBlock(i.toString().toByteArray())
                allBlocks += block.id
                val (peerId, syncMessage) = sourceMember.getSyncMessage()
                assertEquals(false, peerId == sourceMember.self)
                val peerIndex = network.indexOfFirst { it.self == peerId }
                val peer = network[peerIndex]
                val msgSize = syncMessage.serialize().size
                sentSize += msgSize
                ++msgSent
                totalBlocks += syncMessage.blocks.size
                val excess = (peer.blockStore.blocks intersect (syncMessage.blocks.map { it.id }.toSet())).size
                totalExcess += excess
                println("$selfIndex->$peerIndex sent ${syncMessage.blocks.size} $msgSize ${sourceMember.blockStore.blocks.size} ${peer.blockStore.blocks.size} diff ${(sourceMember.blockStore.blocks - peer.blockStore.blocks).size} ${(peer.blockStore.blocks - sourceMember.blockStore.blocks).size} excess $excess")
                peer.processSyncMessage(syncMessage)
            }
        }
        println("average msg size = ${sentSize / msgSent} totalExcess $totalExcess of $totalBlocks")

        var maxDiff = 0
        var diffCount = 0.0
        var diffTotal = 0.0
        var diff2Total = 0.0
        for (member in network) {
            val diff = (allBlocks - member.blockStore.blocks).size
            maxDiff = max(maxDiff, diff)
            ++diffCount
            diffTotal += diff
            diff2Total += diff * diff
        }
        val variance = (diff2Total - ((diffTotal * diffTotal) / diffTotal)) / (diffTotal - 1.0)
        println(
            "total ${allBlocks.size} maxDiff $maxDiff average diff = ${diffTotal / diffCount} stddev = ${
                sqrt(
                    variance
                )
            }"
        )
        assertEquals(
            true,
            (diffTotal / diffCount) < (memberService.members.size * rounds) / 2,
            "Insufficient synchronisation ${diffTotal / diffCount} threshold ${(memberService.members.size * rounds) / 2}"
        )
    }
}