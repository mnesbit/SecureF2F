package uk.co.nesbit.network

import org.apache.avro.Schema
import org.apache.avro.SchemaBuilder
import org.apache.avro.generic.GenericData
import org.apache.avro.generic.GenericRecord
import org.junit.Assert.*
import org.junit.Ignore
import org.junit.Test
import uk.co.nesbit.avro.deserialize
import uk.co.nesbit.avro.getTyped
import uk.co.nesbit.avro.putTyped
import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.api.services.NetworkService
import uk.co.nesbit.network.engineOld.Layer2Node
import uk.co.nesbit.network.engineOld.SimNetwork
import java.util.*
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

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
        val node1 = Layer2Node(net1, 1)
        val node2 = Layer2Node(net2, 1)
        val node3 = Layer2Node(net3, 1)
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
        val node1 = Layer2Node(net1, 1)
        val node2 = Layer2Node(net2, 1)
        val node3 = Layer2Node(net3, 1)
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
        val node1 = Layer2Node(net1, 1)
        val node2 = Layer2Node(net2, 1)
        val node3 = Layer2Node(net3, 1)
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
    fun `link drop test`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val net3 = network.getNetworkService(NetworkAddress(3))
        val node1 = Layer2Node(net1, 1)
        val node2 = Layer2Node(net2, 1)
        val node3 = Layer2Node(net3, 1)
        net1.openLink(net2.networkId)
        net3.openLink(net2.networkId)
        for (i in 0 until 3) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }

        val link2to1Id = node2.neighbourDiscoveryService.findLinkTo(node1.networkId)
        net2.closeLink(link2to1Id!!)
        val link3to2Id = node3.neighbourDiscoveryService.findLinkTo(node2.networkId)
        net3.closeLink(link3to2Id!!)
        for (i in 0 until 3) {
            node1.runStateMachine()
            node2.runStateMachine()
            node3.runStateMachine()
            network.deliverTillEmpty()
        }

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
        for (i in 0 until 4 * n) { // worst case bounds
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

    @Ignore
    @Test
    fun `large random small worlds graph`() {
        val network = SimNetwork()
        val networks = mutableListOf<NetworkService>()
        val n = 100
        val rand = Random()
        for (i in 1..n) {
            networks += network.getNetworkService(NetworkAddress(i))
        }
        val nodes = mutableListOf<Layer2Node>()
        for (i in 0 until n) {
            nodes += Layer2Node(networks[i])
        }
        for (i in 0 until n) {
            if (i > 0) {
                networks[i].openLink(networks[i - 1].networkId)
            }
            if (i < n - 1) {
                networks[i].openLink(networks[i + 1].networkId)
            }
            networks[i].openLink(networks[rand.nextInt(n)].networkId)
        }
        for (i in 0 until 100) { // worst case bounds
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
        val m = 10
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
                    val receiveSubs = node.routeDiscoveryService.onReceive.subscribe { msg ->
                        val i = receivedCount.incrementAndGet()
                        val received = TestMessage(TestMessage.testSchema.deserialize(msg.payload))
                        println("$i ${msg.replyTo} $received")
                        assertEquals(id, received.intField / 100)
                    }
                    for (i in 0 until 4 * n) { // let routing settle
                        node.runStateMachine()
                        Thread.sleep(250)
                    }
                    while (sentCount < m) {
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
                    while (receivedCount.get() < m) {
                        node.runStateMachine()
                        Thread.sleep(250)
                    }
                    receiveSubs.dispose()
                } else {
                    val receiveSubs = node.routeDiscoveryService.onReceive.subscribe { msg ->
                        val i = receivedCount.incrementAndGet()
                        val received = TestMessage(TestMessage.testSchema.deserialize(msg.payload))
                        println("$i ${msg.replyTo} $received")
                        val path = node.routeDiscoveryService.findRandomRouteTo(msg.replyTo)
                        assertNotNull(path)
                        val test1 = RoutedMessage.createRoutedMessage(msg.replyTo, received)
                        node.routeDiscoveryService.send(path!!, test1)
                    }
                    while (receivedCount.get() < m * (n - 1)) {
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

    @Test
    fun `multi-threaded sending`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val net3 = network.getNetworkService(NetworkAddress(3))
        val node1 = Layer2Node(net1)
        val node2 = Layer2Node(net2)
        val node3 = Layer2Node(net3)
        net1.openLink(net2.networkId)
        net3.openLink(net2.networkId)
        val doneCount = AtomicInteger(0)
        node1.routeDiscoveryService.onReceive.subscribe {
            val received = TestMessage(TestMessage.testSchema.deserialize(it.payload))
            if (doneCount.get() < 2 && received.intField != -1) {
                val path = node1.routeDiscoveryService.findRandomRouteTo(it.replyTo)
                if (path != null) {
                    node1.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, TestMessage(-1)))
                }
            }
        }
        node3.routeDiscoveryService.onReceive.subscribe {
            val received = TestMessage(TestMessage.testSchema.deserialize(it.payload))
            if (doneCount.get() < 2 && received.intField != -1) {
                val path = node3.routeDiscoveryService.findRandomRouteTo(it.replyTo)
                if (path != null) {
                    node3.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, TestMessage(-1)))
                }
            }
        }
        val networkThread = thread {
            while (doneCount.get() < 2) {
                network.shuffleMessages()
                network.deliverTillEmpty()
                Thread.sleep(15)
            }
            network.deliverTillEmpty()
        }
        val node1Thread = thread {
            var sendId = 0
            while (sendId < 100) {
                node1.runStateMachine()
                val path = node1.routeDiscoveryService.findRandomRouteTo(node3.neighbourDiscoveryService.networkAddress)
                if (path != null) {
                    node1.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
                }
                val path2 = node3.routeDiscoveryService.findRandomRouteTo(node1.neighbourDiscoveryService.networkAddress)
                if (path2 != null) {
                    node3.routeDiscoveryService.send(path2, RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
                }
                Thread.sleep(200)
            }
            node1.runStateMachine()
            doneCount.incrementAndGet()
            while (doneCount.get() < 2) {
                node1.runStateMachine()
                Thread.sleep(200)
            }
        }
        val node2Thread = thread {
            while (doneCount.get() < 2) {
                node2.runStateMachine()
                Thread.sleep(200)
            }
        }
        val node3Thread = thread {
            var sendId = 0
            while (sendId < 100) {
                node3.runStateMachine()
                val path = node3.routeDiscoveryService.findRandomRouteTo(node1.neighbourDiscoveryService.networkAddress)
                if (path != null) {
                    node3.routeDiscoveryService.send(path, RoutedMessage.createRoutedMessage(node3.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
                }
                val path2 = node1.routeDiscoveryService.findRandomRouteTo(node3.neighbourDiscoveryService.networkAddress)
                if (path2 != null) {
                    node1.routeDiscoveryService.send(path2, RoutedMessage.createRoutedMessage(node1.neighbourDiscoveryService.networkAddress, TestMessage(sendId++)))
                }
                Thread.sleep(200)
            }
            doneCount.incrementAndGet()
            while (doneCount.get() < 2) {
                node3.runStateMachine()
                Thread.sleep(200)
            }
        }

        node1Thread.join()
        node3Thread.join()
        node2Thread.join()
        networkThread.join()
    }

}