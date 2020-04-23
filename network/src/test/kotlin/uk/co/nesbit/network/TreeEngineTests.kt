package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.network.api.tree.Hello
import uk.co.nesbit.network.api.tree.OneHopMessage
import uk.co.nesbit.network.api.tree.TreeState
import uk.co.nesbit.network.engineOld.KeyServiceImpl
import java.security.SignatureException
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import kotlin.test.assertEquals
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

    @Test
    fun `Hello message test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val id = keyService.generateNetworkID("1")
        val hello = Hello.createHello(id, keyService)
        hello.verify()
        val serialized = hello.serialize()
        val deserialized = Hello.deserialize(serialized)
        assertEquals(hello, deserialized)
        deserialized.verify()
    }

    @Test
    fun `TreeState message test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val keys = (0..2).map { keyService.generateNetworkID(it.toString()) }.sorted()
        val id1 = keys[0]
        val linkId12 = keyService.random.generateSeed(16)
        val id2 = keys[1]
        val linkId23 = keyService.random.generateSeed(16)
        val id3 = keys[2]
        val fixedClock = TestClock()
        val treeRootTo1 = TreeState.createTreeState(
            null,
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
            treeRootTo1,
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
        val keys = (0..2).map { keyService.generateNetworkID(it.toString()) }.sorted()
        val id1 = keys[0]
        val linkId12 = keyService.random.generateSeed(16)
        val id2 = keys[2]
        val linkId23 = keyService.random.generateSeed(16)
        val id3 = keys[1]
        val skipClock = TestClock(1L, TreeState.TimeErrorPerHop / 2L)
        val treeRootTo1 = TreeState.createTreeState(
            null,
            linkId12,
            keyService.getVersion(id1),
            keyService.getVersion(id2),
            keyService,
            skipClock.instant()
        )
        val tree1To2 = TreeState.createTreeState(
            treeRootTo1,
            linkId23,
            keyService.getVersion(id2),
            keyService.getVersion(id3),
            keyService,
            skipClock.instant()
        )
        tree1To2.verify(linkId23, keyService.getVersion(id3), skipClock.instant())
        assertFailsWith<IllegalArgumentException> {
            tree1To2.verify(linkId23, keyService.getVersion(id3), skipClock.instant())
        }
    }

    @Test
    fun `Long path test`() {
        val N = 9
        val keyService = KeyServiceImpl(maxVersion = 64)
        val ids = (0..N).map { Pair(keyService.generateNetworkID(it.toString()), keyService.random.generateSeed(16)) }
            .sortedBy { it.first }
        var currTree: TreeState? = null
        for (i in 0 until N) {
            val curr = ids[i]
            val next = ids[i + 1]
            currTree = TreeState.createTreeState(
                currTree,
                curr.second,
                keyService.getVersion(curr.first),
                keyService.getVersion(next.first),
                keyService,
                Clock.systemUTC().instant()
            )
        }
        currTree!!.verify(ids[N - 1].second, keyService.getVersion(ids[N].first), Clock.systemUTC().instant())
        val serialized = currTree.serialize()
        val deserialized = TreeState.deserialize(serialized)
        assertEquals(currTree, deserialized)
        deserialized.verify(ids[N - 1].second, keyService.getVersion(ids[N].first), Clock.systemUTC().instant())

    }

    @Test
    fun `OneHopMessage test`() {
        val keyService = KeyServiceImpl(maxVersion = 64)
        val keys = (0..1).map { keyService.generateNetworkID(it.toString()) }.sorted()
        val id1 = keys[0]
        val id2 = keys[1]
        val helloMessage = Hello.createHello(id2, keyService)
        val treeStateMessage = TreeState.createTreeState(
            null,
            helloMessage.secureLinkId,
            keyService.getVersion(id1),
            keyService.getVersion(id2),
            keyService,
            Clock.systemUTC().instant()
        )
        val oneHopMessage1 = OneHopMessage.createOneHopMessage(1, 0, helloMessage)
        val oneHopMessage1Serialized = oneHopMessage1.serialize()
        val oneHopMessage1Deserialized = OneHopMessage.deserialize(oneHopMessage1Serialized)
        assertEquals(oneHopMessage1, oneHopMessage1Deserialized)
        assertEquals(helloMessage, OneHopMessage.deserializePayload(oneHopMessage1Serialized))
        val oneHopMessage2 = OneHopMessage.createOneHopMessage(2, 1, treeStateMessage)
        val oneHopMessage2Serialized = oneHopMessage2.serialize()
        val oneHopMessage2Deserialized = OneHopMessage.deserialize(oneHopMessage2Serialized)
        assertEquals(oneHopMessage2, oneHopMessage2Deserialized)
        assertEquals(treeStateMessage, OneHopMessage.deserializePayload(oneHopMessage2Serialized))
    }
}