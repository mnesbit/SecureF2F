package uk.co.nesbit.network

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import uk.co.nesbit.network.api.LinkStatus
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.engine.Node
import uk.co.nesbit.network.engine.SimNetwork
import kotlin.test.assertEquals

class LocalLinkTest {
    @Test
    fun `Simple two node network`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Node(net1)
        val node2 = Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 100) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.state.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.state.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.state.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.state.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Send messages between nodes`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Node(net1)
        var receivedOn1: ByteArray? = null
        val node1Subs = node1.neighbourDiscoveryService.onReceive.subscribe {
            receivedOn1 = it.msg
        }
        val node2 = Node(net2)
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
        val node1Address = SphinxAddress(node1.keyService.getVersion(node1.keyService.networkId).identity)
        val node2Address = SphinxAddress(node2.keyService.getVersion(node2.keyService.networkId).identity)
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
    fun `Simple two node network different processing rates`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Node(net1)
        val node2 = Node(net2)
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
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.state.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.state.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.state.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.state.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Link Times out`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Node(net1)
        val node2 = Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.state.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.state.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.state.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.state.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2down = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_DOWN, link1to2down.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2down.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2down.state.route.to)
        assertEquals(null, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
    }

    @Test
    fun `Link Reconnects`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Node(net1)
        val node2 = Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 2) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(0, node1.keyService.getVersion(node1.keyService.networkId).currentVersion.version)
        assertEquals(0, node2.keyService.getVersion(node2.keyService.networkId).currentVersion.version)
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2 = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2.state.route.to)
        assertEquals(link1to2.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1 = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1.state.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1.state.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1.state.route.to)
        assertEquals(link2to1.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2down = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_DOWN, link1to2down.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2down.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2down.state.route.to)
        assertEquals(null, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        for (i in 0 until 4) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }
        assertEquals(1, node1.keyService.getVersion(node1.keyService.networkId).currentVersion.version)
        assertEquals(1, node2.keyService.getVersion(node2.keyService.networkId).currentVersion.version)
        assertEquals(1, node1.neighbourDiscoveryService.links.size)
        val link1to2b = node1.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_ACTIVE, link1to2b.state.status)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link1to2b.state.route.from)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link1to2b.state.route.to)
        assertEquals(link1to2b.linkId, node1.neighbourDiscoveryService.findLinkTo(node2.neighbourDiscoveryService.networkAddress))
        assertEquals(1, node2.neighbourDiscoveryService.links.size)
        val link2to1b = node2.neighbourDiscoveryService.links.values.single()
        assertEquals(LinkStatus.LINK_UP_PASSIVE, link2to1b.state.status)
        assertEquals(node2.neighbourDiscoveryService.networkAddress, link2to1b.state.route.from)
        assertEquals(node1.neighbourDiscoveryService.networkAddress, link2to1b.state.route.to)
        assertEquals(link2to1b.linkId, node2.neighbourDiscoveryService.findLinkTo(node1.neighbourDiscoveryService.networkAddress))

    }
}