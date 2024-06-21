package uk.co.nesbit.network

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.*
import uk.co.nesbit.network.api.tree.Hello.Companion.NONCE_SIZE
import uk.co.nesbit.network.services.KeyServiceImpl
import java.security.SignatureException
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import kotlin.test.assertFailsWith

class TreeEngineTests {
    private class TestClock(var time: Long = 1L, val step: Long = 0L) : Clock() {
        override fun withZone(zone: ZoneId?): Clock {
            throw NotImplementedError()
        }

        override fun getZone(): ZoneId {
            throw NotImplementedError()
        }

        override fun instant(): Instant {
            val now = Instant.ofEpochMilli(time)
            time += step
            return now
        }
    }

    private fun generateKeysAndRoots(keyService: KeyService, n: Int): Pair<List<SecureHash>, List<SecureHash>> {
        val keys = (0 until n + 3).map { keyService.generateNetworkID(it.toString()) }
        val roots = mutableListOf<SecureHash>()
        for (i in 0 until 3) {
            roots += keys.minByOrNull { SecureHash.secureHash(concatByteArrays(i.toByteArray(), it.bytes)) }!!
        }
        val nonRootKeys = keys - roots
        return Pair(nonRootKeys, roots)
    }

    @Test
    fun `Hello message test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val id = keyService.generateNetworkID("1")
        val hello = Hello.createHello(id, keyService)
        hello.verify(keyService)
        val serialized = hello.serialize()
        val deserialized = Hello.deserialize(serialized)
        assertEquals(hello, deserialized)
        deserialized.verify(keyService)
    }

    @Test
    fun `TreeState message test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, 3)
        val id1 = keys[0]
        val linkId12 = keyService.random.generateSeed(NONCE_SIZE)
        val id2 = keys[1]
        val linkId23 = keyService.random.generateSeed(NONCE_SIZE)
        val id3 = keys[2]
        val fixedClock = TestClock()
        val root1 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[0]),
                keyService.getVersion(id1),
                keyService,
                fixedClock.instant()
            )
        )
        val root2 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[1]),
                keyService.getVersion(id1),
                keyService,
                fixedClock.instant()
            )
        )
        val root3 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[2]),
                keyService.getVersion(id1),
                keyService,
                fixedClock.instant()
            )
        )
        val treeRootTo1 = TreeState.createTreeState(
            root1,
            root2,
            root3,
            linkId12,
            keyService.getVersion(id1),
            keyService.getVersion(id2),
            keyService,
            fixedClock.instant()
        )
        treeRootTo1.verify(linkId12, keyService.getVersion(id2), fixedClock.instant())
        val treeRootTo1Serialized = treeRootTo1.serialize()
        val treeRootTo1Deserialized = TreeState.deserialize(treeRootTo1Serialized)
        assertEquals(treeRootTo1, treeRootTo1Deserialized)
        treeRootTo1Deserialized.verify(linkId12, keyService.getVersion(id2), fixedClock.instant())

        val tree1To2 = TreeState.createTreeState(
            treeRootTo1.path1,
            treeRootTo1.path2,
            treeRootTo1.path3,
            linkId23,
            keyService.getVersion(id2),
            keyService.getVersion(id3),
            keyService,
            fixedClock.instant()
        )
        tree1To2.verify(linkId23, keyService.getVersion(id3), fixedClock.instant())
        val tree1To2Serialized = tree1To2.serialize()
        val tree1To2Deserialized = TreeState.deserialize(tree1To2Serialized)
        assertEquals(tree1To2, tree1To2Deserialized)
        tree1To2Deserialized.verify(linkId23, keyService.getVersion(id3), fixedClock.instant())

        assertFailsWith<SignatureException> {
            tree1To2.verify(linkId12, keyService.getVersion(id3), fixedClock.instant())
        }

        assertFailsWith<SignatureException> {
            tree1To2.verify(linkId23, keyService.getVersion(id2), fixedClock.instant())
        }
    }

    @Test
    fun `TreeState time test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, 3)
        val id1 = keys[0]
        val linkId12 = keyService.random.generateSeed(NONCE_SIZE)
        val id2 = keys[1]
        val linkId23 = keyService.random.generateSeed(NONCE_SIZE)
        val id3 = keys[2]
        val root1 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[0]),
                keyService.getVersion(id1),
                keyService,
                Instant.ofEpochMilli(1L)
            )
        )
        val root2 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[1]),
                keyService.getVersion(id1),
                keyService,
                Instant.ofEpochMilli(1L)
            )
        )
        val root3 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[2]),
                keyService.getVersion(id1),
                keyService,
                Instant.ofEpochMilli(1L)
            )
        )

        val skipClock = TestClock(1L, TreeState.TimeErrorPerHop / 2L)
        val treeRootTo1 = TreeState.createTreeState(
            root1,
            root2,
            root3,
            linkId12,
            keyService.getVersion(id1),
            keyService.getVersion(id2),
            keyService,
            skipClock.instant()
        )
        val tree1To2 = TreeState.createTreeState(
            treeRootTo1.path1,
            treeRootTo1.path2,
            treeRootTo1.path3,
            linkId23,
            keyService.getVersion(id2),
            keyService.getVersion(id3),
            keyService,
            skipClock.instant()
        )
        tree1To2.verify(linkId23, keyService.getVersion(id3), skipClock.instant())
        skipClock.instant()
        assertFailsWith<IllegalArgumentException> {
            tree1To2.verify(linkId23, keyService.getVersion(id3), skipClock.instant())
        }
    }

    @Test
    fun `Long path test`() {
        val N = 10
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, N)
        val ids = keys.map { Pair(it, keyService.random.generateSeed(NONCE_SIZE)) }
        val root1 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[0]),
                keyService.getVersion(keys[0]),
                keyService,
                Clock.systemUTC().instant()
            )
        )
        val root2 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[1]),
                keyService.getVersion(keys[0]),
                keyService,
                Clock.systemUTC().instant()
            )
        )
        val root3 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[2]),
                keyService.getVersion(keys[0]),
                keyService,
                Clock.systemUTC().instant()
            )
        )
        var currTree: TreeState? = null
        for (i in 0 until (N - 1)) {
            val curr = ids[i]
            val next = ids[i + 1]
            currTree = TreeState.createTreeState(
                currTree?.path1 ?: root1,
                currTree?.path2 ?: root2,
                currTree?.path3 ?: root3,
                curr.second,
                keyService.getVersion(curr.first),
                keyService.getVersion(next.first),
                keyService,
                Clock.systemUTC().instant()
            )
        }
        currTree!!.verify(ids[N - 2].second, keyService.getVersion(ids[N - 1].first), Clock.systemUTC().instant())
        val serialized = currTree.serialize()
        val deserialized = TreeState.deserialize(serialized)
        assertEquals(currTree, deserialized)
        deserialized.verify(ids[N - 2].second, keyService.getVersion(ids[N - 1].first), Clock.systemUTC().instant())

    }

    @Test
    fun `OneHopMessage test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, 2)
        val id1 = keys[0]
        val id2 = keys[1]
        val fixedClock = TestClock()
        val root1 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[0]),
                keyService.getVersion(id1),
                keyService,
                fixedClock.instant()
            )
        )
        val root2 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[1]),
                keyService.getVersion(id1),
                keyService,
                fixedClock.instant()
            )
        )
        val root3 = SecurePath(
            SecurePath.createSecurePathList(
                null,
                keyService.getVersion(roots[2]),
                keyService.getVersion(id1),
                keyService,
                fixedClock.instant()
            )
        )

        val helloMessage = Hello.createHello(id2, keyService)
        val treeStateMessage = TreeState.createTreeState(
            root1,
            root2,
            root3,
            helloMessage.secureLinkId,
            keyService.getVersion(id1),
            keyService.getVersion(id2),
            keyService,
            Clock.systemUTC().instant()
        )
        val oneHopMessage1 = OneHopMessage.createOneHopMessage(helloMessage)
        val oneHopMessage1Serialized = oneHopMessage1.serialize()
        val oneHopMessage1Deserialized = OneHopMessage.deserialize(oneHopMessage1Serialized)
        assertEquals(oneHopMessage1, oneHopMessage1Deserialized)
        assertEquals(helloMessage, OneHopMessage.deserializePayload(oneHopMessage1Serialized))
        val oneHopMessage2 = OneHopMessage.createOneHopMessage(treeStateMessage)
        val oneHopMessage2Serialized = oneHopMessage2.serialize()
        val oneHopMessage2Deserialized = OneHopMessage.deserialize(oneHopMessage2Serialized)
        assertEquals(oneHopMessage2, oneHopMessage2Deserialized)
        assertEquals(treeStateMessage, OneHopMessage.deserializePayload(oneHopMessage2Serialized))
    }

    @Test
    fun `GreedyRoutedMessage test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, 3)
        val id1 = keyService.getVersion(keys[0])
        val id2 = keyService.getVersion(keys[1])
        val id3 = keyService.getVersion(keys[2])
        val node3Address = NetworkAddressInfo(
            id3,
            listOf(roots[0]) + id3.id,
            listOf(roots[1]) + id3.id,
            listOf(roots[2]) + id3.id
        )
        val message = "1234567890".toByteArray(Charsets.UTF_8)
        val linkId12 = keyService.random.generateSeed(NONCE_SIZE)
        val greedyRoutedMessage = GreedyRoutedMessage.createGreedRoutedMessage(
            node3Address,
            6,
            message,
            linkId12,
            id1,
            id2,
            keyService,
            Clock.systemUTC().instant()
        )
        val serialized1 = greedyRoutedMessage.serialize()
        val deserialized1 = GreedyRoutedMessage.deserialize(serialized1)
        assertEquals(greedyRoutedMessage, deserialized1)
        val result1 = deserialized1.verify(
            id2.id,
            linkId12,
            id1,
            keyService,
            Clock.systemUTC().instant()
        )
        assertEquals(emptyList<VersionedIdentity>(), result1)
        val linkId23 = keyService.random.generateSeed(NONCE_SIZE)
        val greedyRoutedMessage2 = GreedyRoutedMessage.forwardGreedRoutedMessage(
            deserialized1,
            linkId23,
            id2,
            id3,
            keyService,
            Clock.systemUTC().instant()
        )
        val serialized2 = greedyRoutedMessage2.serialize()
        val deserialized2 = GreedyRoutedMessage.deserialize(serialized2)
        assertEquals(greedyRoutedMessage2, deserialized2)
        val result2 = deserialized2.verify(id3.id, linkId23, id2, keyService, Clock.systemUTC().instant())
        assertEquals(listOf(id2, id1), result2)
    }

    @Test
    fun `NetworkAddressInfo test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, 3)
        val id3 = keyService.getVersion(keys[2])
        val node3Address = NetworkAddressInfo(
            id3,
            listOf(roots[0]) + id3.id,
            listOf(roots[1]) + id3.id,
            listOf(roots[2]) + id3.id
        )
        node3Address.verify()
        val serialized = node3Address.serialize()
        val deserialized = NetworkAddressInfo.deserialize(serialized)
        assertEquals(node3Address, deserialized)
    }

    @Test
    fun `SphinxRoutedMessage Test`() {
        val message = "0123456789".toByteArray(Charsets.UTF_8)
        val sphinxRoutedMessage = SphinxRoutedMessage(message)
        val serialized = sphinxRoutedMessage.serialize()
        val deserialized = SphinxRoutedMessage.deserialize(serialized)
        assertEquals(sphinxRoutedMessage, deserialized)
    }

    @Test
    fun `ClientDataMessage serialization test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val (keys, roots) = generateKeysAndRoots(keyService, 3)
        val id1 = keyService.getVersion(keys[2])
        val nodeAddress = NetworkAddressInfo(
            id1,
            listOf(roots[0]) + id1.id,
            listOf(roots[1]) + id1.id,
            listOf(roots[2]) + id1.id
        )
        val message = ClientDataMessage(
            nodeAddress,
            123456789L,
            5555,
            3333,
            0x88,
            23,
            "hello".toByteArray(Charsets.UTF_8)
        )
        val serialized = message.serialize()
        val deserialized = ClientDataMessage.deserialize(serialized)
        assertEquals(message, deserialized)
    }
}