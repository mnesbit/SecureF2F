package uk.co.nesbit.crypto

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.blockdag.*
import java.lang.Integer.min
import java.security.KeyPair
import java.security.PublicKey
import java.security.SignatureException
import kotlin.random.Random
import kotlin.test.assertEquals

class BlockDAGTest {
    @Test
    fun `Round trip serialize block`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = SecureHash.secureHash(keyPair.public.encoded)
        val memberService = object : MemberService {
            override val members: Set<SecureHash>
                get() = setOf(keyId)

            override fun getMemberKey(id: SecureHash): PublicKey? {
                assertEquals(keyId, id)
                return keyPair.public
            }

            override fun addMember(key: PublicKey): SecureHash {
                throw NotImplementedError("Not implemented")
            }
        }
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x).toDigitalSignature()
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
    fun `test block store verify`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = SecureHash.secureHash(keyPair.public.encoded)
        val memberService = object : MemberService {
            override val members: Set<SecureHash>
                get() = setOf(keyId)

            override fun getMemberKey(id: SecureHash): PublicKey? {
                assertEquals(keyId, id)
                return keyPair.public
            }

            override fun addMember(key: PublicKey): SecureHash {
                throw NotImplementedError("Not implemented")
            }
        }
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x).toDigitalSignature()
        }
        val random = Random.Default
        val blockIds = mutableListOf<SecureHash>()
        val blocks = mutableListOf<Block>()
        val rootBlock = Block.createRootBlock(keyId, signingService)
        blockIds += rootBlock.id
        blocks += rootBlock
        for (i in 0 until 500) {
            val inputs = 1 + min(random.nextInt(10), blocks.size - 1)
            val inputIds = mutableSetOf<SecureHash>()
            for (j in 0 until inputs) {
                inputIds += blockIds[random.nextInt(blockIds.size)]
            }
            val newBlock = Block.createBlock(keyId, inputIds.toList(), i.toByteArray(), signingService)
            blockIds += newBlock.id
            blocks += newBlock
        }
        val skipFollower = blocks[blocks.size / 2]
        val skip = skipFollower.predecessors.last()
        val skipBlock = blocks.single { it.id == skip }
        val shuffled = blocks.shuffled()
        val blockStore: BlockStore = InMemoryBlockStore()
        blockStore.transitiveVerify(rootBlock, memberService)
        for (block in shuffled) {
            assertEquals(null, blockStore.getBlock(block.id))
            if (block.id == skip) continue
            blockStore.storeBlock(block)
            assertEquals(block, blockStore.getBlock(block.id))
        }
        assertEquals(1, blockStore.getMissing().size)
        assertEquals(skip, blockStore.getMissing().single())
        blockStore.transitiveVerify(skipBlock, memberService)
        val follows = blockStore.getNext(skip)
        assertEquals(true, skipFollower.id in follows)
        for (next in follows) {
            assertThrows<SignatureException> {
                blockStore.transitiveVerify(blockStore.getBlock(next)!!, memberService)
            }
        }
        blockStore.storeBlock(skipBlock)
        assertEquals(0, blockStore.getMissing().size)
        blockStore.transitiveVerify(blocks.last(), memberService)
        assertEquals(rootBlock.id, blockStore.roots.single())
    }

    @Test
    fun `test block store heads logic`() {
        val keyPair = generateEdDSAKeyPair()
        val keyId = SecureHash.secureHash(keyPair.public.encoded)
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x).toDigitalSignature()
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
        val keyId = SecureHash.secureHash(keyPair.public.encoded)
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x).toDigitalSignature()
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
        val keyId = SecureHash.secureHash(keyPair.public.encoded)
        val signingService = { id: SecureHash, x: ByteArray ->
            assertEquals(keyId, id)
            keyPair.sign(x).toDigitalSignature()
        }
        val memberService = object : MemberService {
            override val members: Set<SecureHash>
                get() = setOf(keyId)

            override fun getMemberKey(id: SecureHash): PublicKey? {
                assertEquals(keyId, id)
                return keyPair.public
            }

            override fun addMember(key: PublicKey): SecureHash {
                throw NotImplementedError("Not implemented")
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
        val syncMessage = BlockSyncMessage.createBlockSyncMessage(
            keyId,
            blockStore.roots,
            blockStore.heads,
            filterSet,
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

    @Test
    fun `BlockSyncManager test`() {
        val random = newSecureRandom()
        val keys = (0..9).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(SecureHash.secureHash(it.public.encoded), it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]

            override fun addMember(key: PublicKey): SecureHash {
                throw NotImplementedError("Not implemented")
            }
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { SecureHash.secureHash(it.public.encoded) }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes).toDigitalSignature()
        }

        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore()
            )
        }

        for (member in network) {
            val rootBlock = Block.createRootBlock(
                member.self,
                signingService
            )
            member.blockStore.storeBlock(rootBlock)
        }

        for (i in 0 until 1000) {
            val member = network[i.rem(network.size)]
            val newBlock = Block.createBlock(
                member.self,
                member.blockStore.heads.toList(),
                i.toString().toByteArray(Charsets.UTF_8),
                signingService
            )
            member.blockStore.storeBlock(newBlock)
            val peer = network[random.nextInt(network.size)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self, signingService)
                println("blocks sent ${syncMessage.blocks.size} ${member.blockStore.blocks.size} ${peer.blockStore.blocks.size} diff ${(member.blockStore.blocks - peer.blockStore.blocks).size} ${(peer.blockStore.blocks - member.blockStore.blocks).size}")
                peer.processSyncMessage(syncMessage)
            }
        }
        for (member1 in network) {
            for (member2 in network) {
                if (member1.self != member2.self) {
                    val sync1 = member1.getSyncMessage(member2.self, signingService)
                    member2.processSyncMessage(sync1)
                    val sync2 = member2.getSyncMessage(member1.self, signingService)
                    member1.processSyncMessage(sync2)
                    val sync3 = member1.getSyncMessage(member2.self, signingService)
                    member2.processSyncMessage(sync3)
                    val sync4 = member2.getSyncMessage(member1.self, signingService)
                    member1.processSyncMessage(sync4)
                }
            }
        }
        for (member in network) {
            assertEquals(network.size, member.blockStore.roots.size)
            assertEquals(true, member.blockStore.getMissing().isEmpty())
            assertEquals(
                network[0].blockStore.blocks,
                member.blockStore.blocks
            )
        }
    }

    @Test
    fun `BlockSyncManager test merging partitioned chains`() {
        val random = newSecureRandom()
        val keys = (0..9).map { generateEdDSAKeyPair(random) }
        val memberService = object : MemberService {
            private val memberMap: Map<SecureHash, PublicKey> =
                keys.associate { Pair(SecureHash.secureHash(it.public.encoded), it.public) }
            override val members: Set<SecureHash> = memberMap.keys

            override fun getMemberKey(id: SecureHash): PublicKey? = memberMap[id]

            override fun addMember(key: PublicKey): SecureHash {
                throw NotImplementedError("Not implemented")
            }
        }
        val keyMap: Map<SecureHash, KeyPair> = keys.associateBy { SecureHash.secureHash(it.public.encoded) }
        val signingService = { id: SecureHash, bytes: ByteArray ->
            keyMap[id]!!.sign(bytes).toDigitalSignature()
        }

        val network = memberService.members.map {
            InMemoryBlockSyncManager(
                it,
                memberService,
                InMemoryBlockStore()
            )
        }

        for (member in network) {
            val rootBlock = Block.createRootBlock(
                member.self,
                signingService
            )
            member.blockStore.storeBlock(rootBlock)
        }

        val halfSize = network.size / 2
        for (i in 0 until 500) {
            val member = network[i.rem(halfSize)]
            val newBlock = Block.createBlock(
                member.self,
                member.blockStore.heads.toList(),
                i.toString().toByteArray(Charsets.UTF_8),
                signingService
            )
            member.blockStore.storeBlock(newBlock)
            val peer = network[random.nextInt(halfSize)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self, signingService)
                peer.processSyncMessage(syncMessage)
            }
        }
        for (i in 0 until 500) {
            val member = network[halfSize + i.rem(network.size - halfSize)]
            val newBlock = Block.createBlock(
                member.self,
                member.blockStore.heads.toList(),
                i.toString().toByteArray(Charsets.UTF_8),
                signingService
            )
            member.blockStore.storeBlock(newBlock)
            val peer = network[halfSize + random.nextInt(network.size - halfSize)]
            if (peer != member) {
                val syncMessage = member.getSyncMessage(peer.self, signingService)
                peer.processSyncMessage(syncMessage)
            }
        }
        for (member1 in network) {
            for (member2 in network) {
                if (member1.self != member2.self) {
                    val sync1 = member1.getSyncMessage(member2.self, signingService)
                    println("blocks sent ${sync1.blocks.size} ${member1.blockStore.blocks.size} ${member2.blockStore.blocks.size} diff ${(member1.blockStore.blocks - member2.blockStore.blocks).size} ${(member2.blockStore.blocks - member1.blockStore.blocks).size}")
                    member2.processSyncMessage(sync1)
                    val sync2 = member2.getSyncMessage(member1.self, signingService)
                    println("blocks sent ${sync2.blocks.size} ${member2.blockStore.blocks.size} ${member1.blockStore.blocks.size} diff ${(member2.blockStore.blocks - member1.blockStore.blocks).size} ${(member1.blockStore.blocks - member2.blockStore.blocks).size}")
                    member1.processSyncMessage(sync2)
                    val sync3 = member1.getSyncMessage(member2.self, signingService)
                    println("blocks sent ${sync3.blocks.size} ${member1.blockStore.blocks.size} ${member2.blockStore.blocks.size} diff ${(member1.blockStore.blocks - member2.blockStore.blocks).size} ${(member2.blockStore.blocks - member1.blockStore.blocks).size}")
                    member2.processSyncMessage(sync3)
                    val sync4 = member2.getSyncMessage(member1.self, signingService)
                    println("blocks sent ${sync4.blocks.size} ${member2.blockStore.blocks.size} ${member1.blockStore.blocks.size} diff ${(member2.blockStore.blocks - member1.blockStore.blocks).size} ${(member1.blockStore.blocks - member2.blockStore.blocks).size}")
                    member1.processSyncMessage(sync4)
                }
            }
        }
        for (member in network) {
            assertEquals(network.size, member.blockStore.roots.size)
            assertEquals(true, member.blockStore.getMissing().isEmpty())
            assertEquals(
                network[0].blockStore.blocks,
                member.blockStore.blocks
            )
        }
    }
}