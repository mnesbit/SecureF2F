package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.newSecureRandom
import uk.co.nesbit.crypto.sign
import uk.co.nesbit.crypto.sphinx.SphinxIdentityKeyPair
import uk.co.nesbit.network.api.routing.*
import kotlin.test.assertEquals

class RoutingDataTest {
    @Test
    fun `VersionedRoute serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPairFrom = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPairTo = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedIDFrom = sphinxIdentityKeyPairFrom.getVersionedId(5)
        val versionedIDTo = sphinxIdentityKeyPairTo.getVersionedId(3)
        val nonce = ByteArray(16)
        random.nextBytes(nonce)
        val versionedRoute = VersionedRoute(SecureHash("SHA-256", VersionedRoute.schemaFingerprint), nonce, versionedIDFrom, versionedIDTo)
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
        val nonce = ByteArray(16)
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
        val nonce1 = ByteArray(16)
        random.nextBytes(nonce1)
        val nonce2 = ByteArray(16)
        random.nextBytes(nonce2)
        val versionedRoute1 = VersionedRoute(SecureHash("SHA-256", VersionedRoute.schemaFingerprint), nonce1, versionedIDFrom, versionedIDTo1)
        val versionedRoute2 = VersionedRoute(SecureHash("SHA-256", VersionedRoute.schemaFingerprint), nonce2, versionedIDFrom, versionedIDTo2)
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
        val sphinxIdentityKeyPairFrom = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPairTo1 = SphinxIdentityKeyPair.generateKeyPair(random)
        val sphinxIdentityKeyPairTo2 = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedIDFrom = sphinxIdentityKeyPairFrom.getVersionedId(5)
        val versionedIDTo1 = sphinxIdentityKeyPairTo1.getVersionedId(3)
        val versionedIDTo2 = sphinxIdentityKeyPairTo2.getVersionedId(4)
        val nonce1 = ByteArray(16)
        random.nextBytes(nonce1)
        val nonce2 = ByteArray(16)
        random.nextBytes(nonce2)
        val versionedRoute1 = VersionedRoute(SecureHash("SHA-256", VersionedRoute.schemaFingerprint), nonce1, versionedIDFrom, versionedIDTo1)
        val versionedRoute2 = VersionedRoute(SecureHash("SHA-256", VersionedRoute.schemaFingerprint), nonce2, versionedIDFrom, versionedIDTo2)
        val route1Serialized = versionedRoute1.serialize()
        val route2Serialized = versionedRoute2.serialize()
        val sig1 = sphinxIdentityKeyPairTo1.signingKeys.sign(route1Serialized).toDigitalSignature()
        val sig2 = sphinxIdentityKeyPairTo2.signingKeys.sign(route2Serialized).toDigitalSignature()
        val sigOver = sphinxIdentityKeyPairFrom.signingKeys.sign(concatByteArrays(sig1.serialize(), sig2.serialize())).toDigitalSignature()
        val routes = Routes(versionedIDFrom,
                listOf(versionedRoute1.entry, versionedRoute2.entry),
                listOf(sig1, sig2),
                sigOver)
        val routeTable = RouteTable(listOf(routes, routes))
        val serialized = routeTable.serialize()
        val deserialized = RouteTable.deserialize(serialized)
        assertEquals(routeTable, deserialized)
        val record = routeTable.toGenericRecord()
        val deserialized2 = RouteTable(record)
        assertEquals(routeTable, deserialized2)
    }

    @Test
    fun `Heartbeat serialization test`() {
        val random = newSecureRandom()
        val sphinxIdentityKeyPairFrom = SphinxIdentityKeyPair.generateKeyPair(random)
        val versionedIDFrom = sphinxIdentityKeyPairFrom.getVersionedId(5)
        val nonce = ByteArray(16)
        random.nextBytes(nonce)
        val heartbeat = Heartbeat(SecureHash("SHA-256", Heartbeat.schemaFingerprint),
                versionedIDFrom.currentVersion,
                sphinxIdentityKeyPairFrom.signingKeys.sign("Test".toByteArray(Charsets.UTF_8)).toDigitalSignature(),
                nonce)
        val serialized = heartbeat.serialize()
        val deserialized = Heartbeat.deserialize(serialized)
        assertEquals(heartbeat, deserialized)
        val record = heartbeat.toGenericRecord()
        val deserialized2 = Heartbeat(record)
        assertEquals(heartbeat, deserialized2)
    }

}