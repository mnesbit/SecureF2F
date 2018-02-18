package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.network.api.LinkStatus
import uk.co.nesbit.network.api.NetworkAddress
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
}