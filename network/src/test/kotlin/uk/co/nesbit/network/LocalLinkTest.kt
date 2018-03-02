package uk.co.nesbit.network

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import uk.co.nesbit.network.api.LinkStatus
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.engine.Layer1Node
import uk.co.nesbit.network.engine.SimNetwork
import java.nio.ByteBuffer
import java.time.Clock
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class LocalLinkTest {
    @Test
    fun `Simple two node network`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 100) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Send messages between nodes`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        var receivedOn1: ByteArray? = null
        val node1Subs = node1.neighbourDiscoveryService.onReceive.subscribe {
            receivedOn1 = it.msg
        }
        val node2 = Layer1Node(net2)
        var receivedOn2: ByteArray? = null
        val node2Subs = node2.neighbourDiscoveryService.onReceive.subscribe {
            receivedOn2 = it.msg
        }
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        val node1Address = node1.neighbourDiscoveryService.networkAddress
        val node2Address = node2.neighbourDiscoveryService.networkAddress
        val link1to2 = node1.neighbourDiscoveryService.findLinkTo(node2Address)
        val testMessage1 = "Test1".toByteArray(Charsets.UTF_8)
        node1.neighbourDiscoveryService.send(link1to2!!, testMessage1)
        network.deliverTillEmpty()
        assertArrayEquals(testMessage1, receivedOn2)
        val link2to1 = node2.neighbourDiscoveryService.findLinkTo(node1Address)
        val testMessage2 = "Test2".toByteArray(Charsets.UTF_8)
        node2.neighbourDiscoveryService.send(link2to1!!, testMessage2)
        network.deliverTillEmpty()
        assertArrayEquals(testMessage2, receivedOn1)
        node1Subs.dispose()
        node2Subs.dispose()
    }

    @Test
    fun `rand messages`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val receivedOn1 = LinkedBlockingQueue<ByteArray>()
        val node1Subs = node1.neighbourDiscoveryService.onReceive.subscribe {
            receivedOn1.offer(it.msg)
        }
        val node2 = Layer1Node(net2)
        val receivedOn2 = LinkedBlockingQueue<ByteArray>()
        val node2Subs = node2.neighbourDiscoveryService.onReceive.subscribe {
            receivedOn2.offer(it.msg)
        }
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            if (node1.keyService.random.nextBoolean()) {
                node1.runStateMachine()
                node2.runStateMachine()
            } else {
                node2.runStateMachine()
                node1.runStateMachine()
            }
            network.shuffleMessages()
            network.deliverTillEmpty()
        }
        val node1Address = node1.neighbourDiscoveryService.networkAddress
        val node2Address = node2.neighbourDiscoveryService.networkAddress
        val link1to2 = node1.neighbourDiscoveryService.findLinkTo(node2Address)
        val link2to1 = node2.neighbourDiscoveryService.findLinkTo(node1Address)
        assertNotNull(link1to2)
        assertNotNull(link2to1)
        for (i in 0 until 100) {
            val testMessage1a = "Test1a_$i".toByteArray(Charsets.UTF_8)
            val testMessage1b = "Test1b_$i".toByteArray(Charsets.UTF_8)
            val testMessage1c = "Test1c_$i".toByteArray(Charsets.UTF_8)
            val testMessage2a = "Test2a_$i".toByteArray(Charsets.UTF_8)
            val testMessage2b = "Test2b_$i".toByteArray(Charsets.UTF_8)
            val testMessage2c = "Test2c_$i".toByteArray(Charsets.UTF_8)
            node1.neighbourDiscoveryService.send(link1to2!!, testMessage1a)
            node2.neighbourDiscoveryService.send(link2to1!!, testMessage2a)
            node1.neighbourDiscoveryService.send(link1to2, testMessage1b)
            node2.neighbourDiscoveryService.send(link2to1, testMessage2b)
            node1.neighbourDiscoveryService.send(link1to2, testMessage1c)
            node2.neighbourDiscoveryService.send(link2to1, testMessage2c)
            if (node1.keyService.random.nextBoolean()) {
                node1.runStateMachine()
                node2.runStateMachine()
            } else {
                node2.runStateMachine()
                node1.runStateMachine()
            }
            network.shuffleMessages()
            network.deliverTillEmpty()
            val message1 = ByteBuffer.wrap(receivedOn1.poll())
            val message2 = ByteBuffer.wrap(receivedOn1.poll())
            val message3 = ByteBuffer.wrap(receivedOn1.poll())
            val messagesA = setOf(message1, message2, message3)
            val expectedMessagesA = setOf(ByteBuffer.wrap(testMessage2a), ByteBuffer.wrap(testMessage2b), ByteBuffer.wrap(testMessage2c))
            assertEquals(expectedMessagesA, messagesA)
            val message4 = ByteBuffer.wrap(receivedOn2.poll())
            val message5 = ByteBuffer.wrap(receivedOn2.poll())
            val message6 = ByteBuffer.wrap(receivedOn2.poll())
            val messagesB = setOf(message4, message5, message6)
            val expectedMessagesB = setOf(ByteBuffer.wrap(testMessage1a), ByteBuffer.wrap(testMessage1b), ByteBuffer.wrap(testMessage1c))
            assertEquals(expectedMessagesB, messagesB)
        }
        node1Subs.dispose()
        node2Subs.dispose()
    }

    @Test
    fun `async test active to passive`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        val receivedOn1 = AtomicInteger(0)
        val node1Subs = node1.neighbourDiscoveryService.onReceive.subscribe {
            val link = node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress)
            assertNotNull(link)
            val i = receivedOn1.incrementAndGet()
            println("1 $i ${it.msg.toString(Charsets.UTF_8)}")
        }
        val receivedOn2 = AtomicInteger(0)
        val node2Subs = node2.neighbourDiscoveryService.onReceive.subscribe {
            val link = node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress)
            assertNotNull(link)
            val i = receivedOn2.incrementAndGet()
            println("2 $i ${it.msg.toString(Charsets.UTF_8)}")
            val msg = "From 2_$i".toByteArray(Charsets.UTF_8)
            node2.neighbourDiscoveryService.send(link!!, msg)
        }
        net1.openLink(net2.networkId)
        var stopping = false
        val networkThread = thread {
            while (!stopping) {
                network.shuffleMessages()
                network.deliverOne()
                Thread.sleep(25)
            }
            network.deliverTillEmpty()
            println("Done network")
        }
        val n = 20
        val node1Thread = thread {
            var lastHeartbeat = Clock.systemUTC().instant().minusMillis(2000)
            var i = 0
            while (receivedOn1.get() < n || receivedOn2.get() < n) {
                val now = Clock.systemUTC().instant()
                if (now.isAfter(lastHeartbeat.plusMillis(1000))) {
                    lastHeartbeat = now
                    node1.runStateMachine()
                }
                if (i < n) {
                    val link = node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress)
                    if (link != null) {
                        val msg = "From 1_$i".toByteArray(Charsets.UTF_8)
                        node1.neighbourDiscoveryService.send(link, msg)
                        ++i
                    }
                }
                Thread.sleep(100)
            }
            println("Node 1 done")
        }
        val node2Thread = thread {
            var lastHeartbeat = Clock.systemUTC().instant().minusMillis(2000)
            while (receivedOn1.get() < n || receivedOn2.get() < n) {
                val now = Clock.systemUTC().instant()
                if (now.isAfter(lastHeartbeat.plusMillis(1000))) {
                    lastHeartbeat = now
                    node2.runStateMachine()
                }
                Thread.sleep(100)
            }
            println("Node 2 done")
        }
        node1Thread.join()
        node2Thread.join()
        stopping = true
        networkThread.join()
        assertEquals(n, receivedOn1.get())
        assertEquals(n, receivedOn2.get())
        node1Subs.dispose()
        node2Subs.dispose()
    }

    @Test
    fun `async test passive to active`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        val receivedOn1 = AtomicInteger(0)
        val node1Subs = node1.neighbourDiscoveryService.onReceive.subscribe {
            val link = node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress)
            assertNotNull(link)
            val i = receivedOn1.incrementAndGet()
            println("1 $i ${it.msg.toString(Charsets.UTF_8)}")
        }
        val receivedOn2 = AtomicInteger(0)
        val node2Subs = node2.neighbourDiscoveryService.onReceive.subscribe {
            val link = node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress)
            assertNotNull(link)
            val i = receivedOn2.incrementAndGet()
            println("2 $i ${it.msg.toString(Charsets.UTF_8)}")
            val msg = "From 2_$i".toByteArray(Charsets.UTF_8)
            node2.neighbourDiscoveryService.send(link!!, msg)
        }
        net2.openLink(net1.networkId)
        var stopping = false
        val networkThread = thread {
            while (!stopping) {
                network.shuffleMessages()
                network.deliverOne()
                Thread.sleep(25)
            }
            network.deliverTillEmpty()
            println("Done network")
        }
        val n = 20
        val node1Thread = thread {
            var lastHeartbeat = Clock.systemUTC().instant().minusMillis(2000)
            var i = 0
            while (receivedOn1.get() < n || receivedOn2.get() < n) {
                val now = Clock.systemUTC().instant()
                if (now.isAfter(lastHeartbeat.plusMillis(1000))) {
                    lastHeartbeat = now
                    node1.runStateMachine()
                }
                if (i < n) {
                    val link = node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress)
                    if (link != null) {
                        val msg = "From 1_$i".toByteArray(Charsets.UTF_8)
                        node1.neighbourDiscoveryService.send(link, msg)
                        ++i
                    }
                }
                Thread.sleep(100)
            }
            println("Node 1 done")
        }
        val node2Thread = thread {
            var lastHeartbeat = Clock.systemUTC().instant().minusMillis(2000)
            while (receivedOn1.get() < n || receivedOn2.get() < n) {
                val now = Clock.systemUTC().instant()
                if (now.isAfter(lastHeartbeat.plusMillis(1000))) {
                    lastHeartbeat = now
                    node2.runStateMachine()
                }
                Thread.sleep(100)
            }
            println("Node 2 done")
        }
        node1Thread.join()
        node2Thread.join()
        stopping = true
        networkThread.join()
        assertEquals(n, receivedOn1.get())
        assertEquals(n, receivedOn2.get())
        node1Subs.dispose()
        node2Subs.dispose()
    }

    @Test
    fun `multi threaded send`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        val receivedOn2 = AtomicInteger(0)
        val node2Subs = node2.neighbourDiscoveryService.onReceive.subscribe {
            val link = node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress)
            assertNotNull(link)
            val i = receivedOn2.incrementAndGet()
            println("2 $i ${it.msg.toString(Charsets.UTF_8)}")
            val msg = "From 2_$i".toByteArray(Charsets.UTF_8)
            node2.neighbourDiscoveryService.send(link!!, msg)
        }
        net1.openLink(net2.networkId)
        var stopping = false
        val networkThread = thread {
            while (!stopping) {
                network.shuffleMessages()
                network.deliverTillEmpty()
                Thread.sleep(25)
            }
            network.deliverTillEmpty()
            println("Done network")
        }
        val node1HeartbeatThread = thread {
            var lastHeartbeat = Clock.systemUTC().instant().minusMillis(2000)
            while (!stopping) {
                val now = Clock.systemUTC().instant()
                if (now.isAfter(lastHeartbeat.plusMillis(1000))) {
                    lastHeartbeat = now
                    node1.runStateMachine()
                }
                Thread.sleep(100)
            }
            println("Node 1a done")
        }
        val node2HeartbeatThread = thread {
            var lastHeartbeat = Clock.systemUTC().instant().minusMillis(2000)
            while (!stopping) {
                val now = Clock.systemUTC().instant()
                if (now.isAfter(lastHeartbeat.plusMillis(1000))) {
                    lastHeartbeat = now
                    node2.runStateMachine()
                }
                Thread.sleep(100)
            }
            println("Node 1a done")
        }
        val n = 20
        val node1Thread1 = thread {
            var i = 0
            while (receivedOn2.get() < 2 * n) {
                if (i < n) {
                    val link = node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress)
                    if (link != null) {
                        val msg = "From 1a_$i".toByteArray(Charsets.UTF_8)
                        node1.neighbourDiscoveryService.send(link, msg)
                        ++i
                    }
                }
                Thread.sleep(100)
            }
            println("Node 1a done")
        }
        val node1Thread2 = thread {
            var i = 0
            while (receivedOn2.get() < 2 * n) {
                if (i < n) {
                    val link = node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress)
                    if (link != null) {
                        val msg = "From 1a_$i".toByteArray(Charsets.UTF_8)
                        node1.neighbourDiscoveryService.send(link, msg)
                        ++i
                    }
                }
                Thread.sleep(100)
            }
            println("Node 1b done")
        }
        node1Thread1.join()
        node1Thread2.join()
        stopping = true
        node1HeartbeatThread.join()
        node2HeartbeatThread.join()
        networkThread.join()
        assertEquals(2 * n, receivedOn2.get())
        node2Subs.dispose()
    }

    @Test
    fun `Simple two node network different processing rates`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 50) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        for (i in 0 until 50) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
            node1.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Link Times out`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2down = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_DOWN, link1to2down.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2down.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2down.route.to)
        assertEquals(null, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Link Reconnects passive end failure`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(0, node1.keyService.getVersion(node1.networkAddress.id).currentVersion.version)
        assertEquals(0, node2.keyService.getVersion(node2.networkAddress.id).currentVersion.version)
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2down = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_DOWN, link1to2down.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2down.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2down.route.to)
        assertEquals(null, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.keyService.getVersion(node1.networkAddress.id).currentVersion.version)
        assertEquals(1, node2.keyService.getVersion(node2.networkAddress.id).currentVersion.version)
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2b = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2b.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2b.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2b.route.to)
        assertEquals(link1to2b.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1b = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1b.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1b.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1b.route.to)
        assertEquals(link2to1b.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Link Reconnects active end failure`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer1Node(net1)
        val node2 = Layer1Node(net2)
        net2.openLink(net1.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(0, node1.keyService.getVersion(node1.networkAddress.id).currentVersion.version)
        assertEquals(0, node2.keyService.getVersion(node2.networkAddress.id).currentVersion.version)
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link1to2.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link2to1.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2down = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_DOWN, link1to2down.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2down.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2down.route.to)
        assertEquals(null, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.keyService.getVersion(node1.networkAddress.id).currentVersion.version)
        assertEquals(1, node2.keyService.getVersion(node2.networkAddress.id).currentVersion.version)
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2b = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link1to2b.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2b.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2b.route.to)
        assertEquals(link1to2b.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1b = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link2to1b.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1b.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1b.route.to)
        assertEquals(link2to1b.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
    }
}