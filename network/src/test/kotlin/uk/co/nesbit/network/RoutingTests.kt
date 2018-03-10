package uk.co.nesbit.network

import org.apache.avro.Schema
import org.apache.avro.SchemaBuilder
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.junit.Test
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.api.services.NetworkService
import uk.co.nesbit.network.engine.Layer2Node
import uk.co.nesbit.network.engine.SimNetwork
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoutingTests {
    private data class TestMessage(private val intField: Int) : Message {
        constructor(testRecord: GenericRecord) : this(testRecord.getTyped<Int>("intField"))

        companion object {
            val testSchema: Schema = SchemaBuilder.record("test1").fields().requiredInt("intField").endRecord()
        }

        override fun toGenericRecord(): GenericRecord {
            val testRecord = GenericData.Record(testSchema)
            testRecord.putTyped("intField", intField)
            return testRecord
        }
    }
    @Test
    fun `simple two node network`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer2Node(net1)
        val node2 = Layer2Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.routeDiscoveryService.knownAddresses.size)
        assertTrue(node2.neighbourDiscoveryService.networkAddress in node1.routeDiscoveryService.knownAddresses)
        assertEquals(1, node2.routeDiscoveryService.knownAddresses.size)
        assertTrue(node1.neighbourDiscoveryService.networkAddress in node2.routeDiscoveryService.knownAddresses)
        println(network.messageCount)
    }

    @Test
    fun `three nodes in a line`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val net3 = network.getNetworkService(NetworkAddress(3))
        val node1 = Layer2Node(net1)
        val node2 = Layer2Node(net2)
        val node3 = Layer2Node(net3)
        net1.openLink(net2.networkId)
        net3.openLink(net2.networkId)
        for (i in 0 until 3) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(2, node1.routeDiscoveryService.knownAddresses.size)
        assertTrue(node2.neighbourDiscoveryService.networkAddress in node1.routeDiscoveryService.knownAddresses)
        assertTrue(node3.neighbourDiscoveryService.networkAddress in node1.routeDiscoveryService.knownAddresses)
        assertEquals(2, node2.routeDiscoveryService.knownAddresses.size)
        assertTrue(node1.neighbourDiscoveryService.networkAddress in node2.routeDiscoveryService.knownAddresses)
        assertTrue(node3.neighbourDiscoveryService.networkAddress in node2.routeDiscoveryService.knownAddresses)
        assertEquals(2, node3.routeDiscoveryService.knownAddresses.size)
        assertTrue(node1.neighbourDiscoveryService.networkAddress in node3.routeDiscoveryService.knownAddresses)
        assertTrue(node2.neighbourDiscoveryService.networkAddress in node3.routeDiscoveryService.knownAddresses)
        println(network.messageCount)
    }

    @Test
    fun `three nodes in a line 2`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val net3 = network.getNetworkService(NetworkAddress(3))
        val node1 = Layer2Node(net1)
        val node2 = Layer2Node(net2)
        val node3 = Layer2Node(net3)
        net2.openLink(net1.networkId)
        net2.openLink(net3.networkId)
        for (i in 0 until 3) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(2, node1.routeDiscoveryService.knownAddresses.size)
        assertTrue(node2.neighbourDiscoveryService.networkAddress in node1.routeDiscoveryService.knownAddresses)
        assertTrue(node3.neighbourDiscoveryService.networkAddress in node1.routeDiscoveryService.knownAddresses)
        assertEquals(2, node2.routeDiscoveryService.knownAddresses.size)
        assertTrue(node1.neighbourDiscoveryService.networkAddress in node2.routeDiscoveryService.knownAddresses)
        assertTrue(node3.neighbourDiscoveryService.networkAddress in node2.routeDiscoveryService.knownAddresses)
        assertEquals(2, node3.routeDiscoveryService.knownAddresses.size)
        assertTrue(node1.neighbourDiscoveryService.networkAddress in node3.routeDiscoveryService.knownAddresses)
        assertTrue(node2.neighbourDiscoveryService.networkAddress in node3.routeDiscoveryService.knownAddresses)
        println(network.messageCount)
    }

    @Test
    fun `send messages through intermediate node`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val net3 = network.getNetworkService(NetworkAddress(3))
        val node1 = Layer2Node(net1)
        val node2 = Layer2Node(net2)
        val node3 = Layer2Node(net3)
        net1.openLink(net2.networkId)
        net3.openLink(net2.networkId)
        for (i in 0 until 3) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }
        val receivedOn1 = node1.routeDiscoveryService.onReceive.blockingIterable().iterator()
        val receivedOn3 = node3.routeDiscoveryService.onReceive.blockingIterable().iterator()
        val msg1 = TestMessage(1)
        val test1 = RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, msg1)
        val route1to3 = node1.routeDiscoveryService.findRandomRouteTo(node3.neighbourDiscoveryService.networkAddress)!!
        assertEquals(listOf(node2.neighbourDiscoveryService.networkAddress, node3.neighbourDiscoveryService.networkAddress), route1to3)
        node1.routeDiscoveryService.send(route1to3, test1)
        for (i in 0 until 1) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }
        val routed = receivedOn3.next()
        assertEquals(test1, routed)
        val msg2 = TestMessage(2)
        val test2 = RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, msg2)
        val route3to1 = node3.routeDiscoveryService.findRandomRouteTo(node1.neighbourDiscoveryService.networkAddress)!!
        assertEquals(listOf(node2.neighbourDiscoveryService.networkAddress, node1.neighbourDiscoveryService.networkAddress), route3to1)
        node3.routeDiscoveryService.send(route3to1, test2)
        for (i in 0 until 1) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }
        val routed2 = receivedOn1.next()
        assertEquals(test2, routed2)
    }

    @Test
    fun `n nodes in a line`() {
        val network = SimNetwork()
        val networks = mutableListOf<NetworkService>()
        val n = 20
        for (i in 1..n) {
            networks += network.getNetworkService(NetworkAddress(i))
        }
        val nodes = mutableListOf<Layer2Node>()
        for (i in 0 until n) {
            nodes += Layer2Node(networks[i])
        }
        for (i in 0 until n - 1) {
            networks[i].openLink((networks[i + 1]).networkId)
        }
        for (i in 0 until 2 * n) { // worst case bounds
            println("round $i")
            nodes.forEach { it.runStateMachine() }
            network.deliverTillEmpty()
            var allDone = true
            for (node in nodes) {
                if (node.routeDiscoveryService.knownAddresses.size < n - 1) allDone = false
                println("${node.networkId} ${node.routeDiscoveryService.knownAddresses.size}")
            }
            if (allDone) break // exit early if we can
        }
        for (node in nodes) {
            assertEquals(n - 1, node.routeDiscoveryService.knownAddresses.size)
            for (node2 in nodes) {
                if (node !== node2) {
                    assertTrue(node2.neighbourDiscoveryService.networkAddress in node.routeDiscoveryService.knownAddresses)
                }
            }
        }
        println(network.messageCount)
        println(network.bytesSent)
    }
}