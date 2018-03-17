package uk.co.nesbit.network

import org.apache.avro.Schema
import org.apache.avro.SchemaBuilder
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.junit.Test
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.api.services.NetworkService
import uk.co.nesbit.network.engine.Layer2Node
import uk.co.nesbit.network.engine.SimNetwork
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RoutingTests {
    private data class TestMessage(val intField: Int) : Message {
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


    @Test
    fun `async routing`() {
        val network = SimNetwork()
        val networks = mutableListOf<NetworkService>()
        val n = 5
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
        var stopping = false
        val networkThread = thread {
            while (!stopping) {
                network.shuffleMessages()
                network.deliverTillEmpty()
                Thread.sleep(15)
            }
            network.deliverTillEmpty()
        }
        val threads = Array(n) {
            thread(name = "node $it") {
                val id = it + 1
                val node = nodes[it]
                val target = nodes[n - 1].neighbourDiscoveryService.networkAddress
                var sentCount = 0
                val receivedCount = AtomicInteger(0)
                if (id != n) {
                    val receiveSubs = node.routeDiscoveryService.onReceive.subscribe {
                        val i = receivedCount.incrementAndGet()
                        val received = TestMessage(TestMessage.testSchema.deserialize(it.payload))
                        println("$i ${it.replyTo} $received")
                        assertEquals(id, received.intField / 100)
                    }
                    while (sentCount < 10) {
                        node.runStateMachine()
                        Thread.sleep(250)
                        if (node.routeDiscoveryService.knownAddresses.contains(target)) {
                            val route1toN = node.routeDiscoveryService.findRandomRouteTo(target)!!
                            val msg1 = TestMessage(100 * id + sentCount)
                            ++sentCount
                            val test1 = RoutedMessage.createRoutedMessage(node.neighbourDiscoveryService.networkAddress, msg1)
                            node.routeDiscoveryService.send(route1toN, test1)
                        }
                    }
                    while (receivedCount.get() < 10) {
                        node.runStateMachine()
                        Thread.sleep(250)
                    }
                    receiveSubs.dispose()
                } else {
                    val receiveSubs = node.routeDiscoveryService.onReceive.subscribe {
                        val i = receivedCount.incrementAndGet()
                        val received = TestMessage(TestMessage.testSchema.deserialize(it.payload))
                        println("$i ${it.replyTo} $received")
                        val path = node.routeDiscoveryService.findRandomRouteTo(it.replyTo)
                        assertNotNull(path)
                        val test1 = RoutedMessage.createRoutedMessage(it.replyTo, received)
                        node.routeDiscoveryService.send(path!!, test1)
                    }
                    while (receivedCount.get() < 10 * (n - 1)) {
                        node.runStateMachine()
                        Thread.sleep(250)
                    }
                    receiveSubs.dispose()
                }
            }
        }
        for (thread in threads) {
            thread.join()
        }
        stopping = true
        networkThread.join()
    }

}