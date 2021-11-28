package uk.co.nesbit.crypto

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.blockdag.Block
import uk.co.nesbit.crypto.blockdag.InMemoryBlockStore
import uk.co.nesbit.crypto.blockdag.MemberService
import java.lang.Integer.min
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
        val blockStore = InMemoryBlockStore()
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
        val blockStore = InMemoryBlockStore()
        for (block in shuffled) {
            blockStore.storeBlock(block)
        }
        assertEquals(heads, blockStore.heads)
        assertEquals(emptySet(), blockStore.followSet(heads))
        assertEquals(blockIds.toSet().minus(rootBlock.id), blockStore.followSet(setOf(rootBlock.id)))
    }

}