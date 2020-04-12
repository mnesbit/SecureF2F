package uk.co.nesbit.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.*
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.network.api.routing.*
import uk.co.nesbit.network.api.routing.VersionedRoute.Companion.NONCE_SIZE
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.engineOld.KeyServiceImpl
import java.security.SignatureException
import kotlin.experimental.xor
import kotlin.test.assertFailsWith

class RoutingDataTest {
    @Test
    fun `VersionedRoute serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPairFrom = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPairTo = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedIDFrom = sphinxIdentityKeyPairFrom.getVersionedId(5)
        val versionedIDTo = sphinxIdentityKeyPairTo.getVersionedId(3)
        val nonce = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce)
        val versionedRoute = VersionedRoute(nonce, versionedIDFrom, versionedIDTo)
        val serialized = versionedRoute.serialize()
        val deserialized = VersionedRoute.deserialize(serialized)
        assertEquals(versionedRoute, deserialized)
        val record = versionedRoute.toGenericRecord()
        val deserialized2 = VersionedRoute(record)
        assertEquals(versionedRoute, deserialized2)
    }

    @Test
    fun `RouteEntry serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPair = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedID = sphinxIdentityKeyPair.getVersionedId(3)
        val nonce = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce)
        val routeEntry = RouteEntry(nonce, versionedID)
        val serialized = routeEntry.serialize()
        val deserialized = RouteEntry.deserialize(serialized)
        assertEquals(routeEntry, deserialized)
        val record = routeEntry.toGenericRecord()
        val deserialized2 = RouteEntry(record)
        assertEquals(routeEntry, deserialized2)
    }

    @Test
    fun `Routes serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPairFrom = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPairTo1 = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPairTo2 = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedIDFrom = sphinxIdentityKeyPairFrom.getVersionedId(5)
        val versionedIDTo1 = sphinxIdentityKeyPairTo1.getVersionedId(3)
        val versionedIDTo2 = sphinxIdentityKeyPairTo2.getVersionedId(4)
        val nonce1 = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce1)
        val nonce2 = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce2)
        val versionedRoute1 = VersionedRoute(nonce1, versionedIDFrom, versionedIDTo1)
        val versionedRoute2 = VersionedRoute(nonce2, versionedIDFrom, versionedIDTo2)
        val route1Serialized = versionedRoute1.serialize()
        val route2Serialized = versionedRoute2.serialize()
        val sig1 = sphinxIdentityKeyPairTo1.signingKeys.sign(route1Serialized).toDigitalSignature()
        val sig2 = sphinxIdentityKeyPairTo2.signingKeys.sign(route2Serialized).toDigitalSignature()
        val sigOver = sphinxIdentityKeyPairFrom.signingKeys.sign(concatByteArrays(route1Serialized, route2Serialized)).toDigitalSignature()
        val routes = Routes(versionedIDFrom,
                listOf(versionedRoute1.entry, versionedRoute2.entry),
                listOf(sig1, sig2),
                sigOver)

        val serialized = routes.serialize()
        val deserialized = Routes.deserialize(serialized)
        assertEquals(routes, deserialized)
        val record = routes.toGenericRecord()
        val deserialized2 = Routes(record)
        assertEquals(routes, deserialized2)
    }


    @Test
    fun `RouteTable serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyService: KeyService = KeyServiceImpl(random)
        val fromId = sphinxIdentityKeyService.generateNetworkID()
        val sphinxIdentityKeyPairTo1: KeyService = KeyServiceImpl(random)
        val idTo1 = sphinxIdentityKeyPairTo1.generateNetworkID()
        val sphinxIdentityKeyPairTo2: KeyService = KeyServiceImpl(random)
        val idTo2 = sphinxIdentityKeyPairTo2.generateNetworkID()
        val versionedIDFrom = sphinxIdentityKeyService.incrementAndGetVersion(fromId)
        sphinxIdentityKeyPairTo1.incrementAndGetVersion(idTo1)
        val versionedIDTo1 = sphinxIdentityKeyPairTo1.incrementAndGetVersion(idTo1)
        sphinxIdentityKeyPairTo2.incrementAndGetVersion(idTo2)
        sphinxIdentityKeyPairTo2.incrementAndGetVersion(idTo2)
        val versionedIDTo2 = sphinxIdentityKeyPairTo2.incrementAndGetVersion(idTo2)
        val nonce1 = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce1)
        val nonce2 = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce2)
        val nonce3 = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce3)
        val versionedRoute1 = VersionedRoute(nonce1, versionedIDFrom, versionedIDTo1)
        val versionedRoute2 = VersionedRoute(nonce2, versionedIDFrom, versionedIDTo2)
        val versionedRoute3 = VersionedRoute(nonce3, versionedIDTo2, versionedIDFrom)
        val route1Serialized = versionedRoute1.serialize()
        val route2Serialized = versionedRoute2.serialize()
        val route3Serialized = versionedRoute3.serialize()
        val sig1 = sphinxIdentityKeyPairTo1.sign(idTo1, route1Serialized).toDigitalSignature()
        val sig2 = sphinxIdentityKeyPairTo2.sign(idTo2, route2Serialized).toDigitalSignature()
        val sig3 = sphinxIdentityKeyService.sign(fromId, route3Serialized).toDigitalSignature()
        val routeEntries1 = listOf(SignedEntry(versionedRoute1.entry, sig1), SignedEntry(versionedRoute2.entry, sig2))
        val routes1 = Routes.createRoutes(routeEntries1, sphinxIdentityKeyService, fromId)
        routes1.verify()
        val routeEntries2 = listOf(SignedEntry(versionedRoute3.entry, sig3))
        val routes2 = Routes.createRoutes(routeEntries2, sphinxIdentityKeyPairTo2, idTo2)
        routes2.verify()
        val bloomFilter = BloomFilter(10, 0.02, 11)
        bloomFilter.add(versionedIDFrom.serialize())
        val routeTable = RouteTable(listOf(routes1, routes2), bloomFilter, null)
        val serialized = routeTable.serialize()
        val deserialized = RouteTable.deserialize(serialized)
        assertEquals(routeTable, deserialized)
        assertEquals(true, deserialized.knownSources.possiblyContains(versionedIDFrom.serialize()))
        val record = routeTable.toGenericRecord()
        val deserialized2 = RouteTable(record)
        assertEquals(routeTable, deserialized2)
        val routeTable2 = RouteTable(listOf(routes1, routes2), BloomFilter.EmptyFilter, fromId)
        val serialized3 = routeTable2.serialize()
        val deserialized3 = RouteTable.deserialize(serialized3)
        assertEquals(routeTable2, deserialized3)
        val record2 = routeTable2.toGenericRecord()
        val deserialized4 = RouteTable(record2)
        assertEquals(routeTable2, deserialized4)
        val badTable = RouteTable(listOf(routes1, routes2), BloomFilter.EmptyFilter, idTo1)
        assertFailsWith<IllegalArgumentException> {
            badTable.verify()
        }
    }

    @Test
    fun `Heartbeat serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPairFrom = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedIDFrom = sphinxIdentityKeyPairFrom.getVersionedId(5)
        val nonce = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce)
        val heartbeat = Heartbeat(versionedIDFrom.currentVersion,
                sphinxIdentityKeyPairFrom.signingKeys.sign("Test".toByteArray(Charsets.UTF_8)).toDigitalSignature(),
                nonce)
        val serialized = heartbeat.serialize()
        val deserialized = Heartbeat.deserialize(serialized)
        assertEquals(heartbeat, deserialized)
        val record = heartbeat.toGenericRecord()
        val deserialized2 = Heartbeat(record)
        assertEquals(heartbeat, deserialized2)
        val deserialized3 = Heartbeat.tryDeserialize(serialized)
        assertEquals(heartbeat, deserialized3)
        assertNull(Heartbeat.tryDeserialize(serialized.copyOf(serialized.size - 1)))
        assertNull(Heartbeat.tryDeserialize(serialized.copyOf(serialized.size + 1)))
        serialized[0] = 0
        assertNull(Heartbeat.tryDeserialize(serialized))
    }

    @Test
    fun `Generation and validation of Heartbeats`() {
        val aliceKeyService: KeyService = KeyServiceImpl()
        val aliceId = aliceKeyService.generateNetworkID()
        aliceKeyService.incrementAndGetVersion(aliceId)
        val bobKeyService: KeyService = KeyServiceImpl()
        val bobId = bobKeyService.generateNetworkID()
        var aliceIdentity = aliceKeyService.getVersion(aliceId)
        var bobIdentity = bobKeyService.getVersion(bobId)
        var aliceNonce: ByteArray
        var bobNonce = ByteArray(NONCE_SIZE, { i -> i.toByte() })
        for (i in 0 until 30) {
            if ((i.rem(3)) == 1) {
                aliceKeyService.incrementAndGetVersion(aliceId)
            }
            val aliceHeartbeat1 = Heartbeat.createHeartbeat(bobNonce, bobIdentity, aliceKeyService, aliceId)
            aliceIdentity = aliceHeartbeat1.verify(bobNonce, bobIdentity, aliceIdentity)
            aliceNonce = aliceHeartbeat1.nextExpectedNonce
            if ((i.rem(5)) == 2) {
                bobKeyService.incrementAndGetVersion(bobId)
            }
            val bobHeartbeat1 = Heartbeat.createHeartbeat(aliceNonce, aliceIdentity, bobKeyService, bobId)
            bobIdentity = bobHeartbeat1.verify(aliceNonce, aliceIdentity, bobIdentity)
            bobNonce = bobHeartbeat1.nextExpectedNonce
        }
    }

    @Test
    fun `Ping Pong verification test`() {
        val keyService: KeyService = KeyServiceImpl()
        val networkId = keyService.generateNetworkID()
        val ping = Ping.createPing(keyService)
        val serializedPing = ping.serialize()
        val deserializedPing = Ping.deserialize(serializedPing)
        assertEquals(ping, deserializedPing)
        val tryDeserializedPing = Ping.tryDeserialize(serializedPing)!!
        assertEquals(ping, tryDeserializedPing)
        serializedPing[2] = serializedPing[2] xor 1
        val failedDeserialize = Ping.tryDeserialize(serializedPing)
        assertNull(failedDeserialize)
        val pong = Pong.createPong(ping, networkId, keyService)
        val serializedPong = pong.serialize()
        val deserializedPong = Pong.deserialize(serializedPong)
        assertEquals(pong, deserializedPong)
        val tryDeserializedPong = Pong.tryDeserialize(serializedPong)!!
        assertEquals(pong, tryDeserializedPong)
        serializedPong[2] = serializedPong[2] xor 1
        val failedDeserialize2 = Ping.tryDeserialize(serializedPong)
        assertNull(failedDeserialize2)
        pong.verify(ping)
        assertFailsWith(SignatureException::class) {
            pong.verify(Ping.createPing(keyService))
        }
    }

    @Test
    fun `ReplyPath test`() {
        val keyService: KeyService = KeyServiceImpl()
        val id1 = keyService.generateNetworkID("1")
        val id2 = keyService.generateNetworkID("2")
        val id3 = keyService.generateNetworkID("3")
        val idList = listOf(id1, id2, id3).map { keyService.getVersion(it).identity }
        val replyPath = ReplyPath(idList)
        val serializedPath = replyPath.serialize()
        val deserializedPath = ReplyPath.deserialize(serializedPath)
        assertEquals(replyPath, deserializedPath)
    }

    @Test
    fun `DhtRequest test`() {
        val keyService: KeyService = KeyServiceImpl()
        val id1 = keyService.generateNetworkID("1")
        val id2 = keyService.generateNetworkID("2")
        val id3 = keyService.generateNetworkID("3")
        val idList = listOf(id1, id2, id3).map { keyService.getVersion(it).identity }
        val replyPath = ReplyPath(idList)
        val key = SecureHash.secureHash("test")
        val dhtRequest1 = DhtRequest(123456L, key, replyPath, null)
        val serializedRequest1 = dhtRequest1.serialize()
        val deserializedRequest1 = DhtRequest.deserialize(serializedRequest1)
        assertEquals(dhtRequest1, deserializedRequest1)
        val dhtRequest2 = DhtRequest(123456L, key, replyPath, "TestBytes".toByteArray())
        val serializedRequest2 = dhtRequest2.serialize()
        val deserializedRequest2 = DhtRequest.deserialize(serializedRequest2)
        assertEquals(dhtRequest2, deserializedRequest2)
    }

    @Test
    fun `DhtResponse test`() {
        val keyService: KeyService = KeyServiceImpl()
        val id1 = keyService.generateNetworkID("1")
        val id2 = keyService.generateNetworkID("2")
        val id3 = keyService.generateNetworkID("3")
        val id4 = keyService.generateNetworkID("4")
        val id5 = keyService.generateNetworkID("5")
        val id6 = keyService.generateNetworkID("6")
        val idList1 = listOf(id1, id2, id3).map { keyService.getVersion(it).identity }
        val idList2 = listOf(id4, id5, id6).map { keyService.getVersion(it).identity }
        val replyPath1 = ReplyPath(idList1)
        val replyPath2 = ReplyPath(idList2)
        val dhtResponse1 = DhtResponse(123456L, listOf(replyPath1, replyPath2), null)
        val serializedResponse1 = dhtResponse1.serialize()
        val deserializedResponse1 = DhtResponse.deserialize(serializedResponse1)
        assertEquals(dhtResponse1, deserializedResponse1)
        val dhtResponse2 = DhtResponse(123456L, listOf(replyPath1, replyPath2), "test bytes".toByteArray())
        val serializedResponse2 = dhtResponse2.serialize()
        val deserializedResponse2 = DhtResponse.deserialize(serializedResponse2)
        assertEquals(dhtResponse2, deserializedResponse2)
    }
}