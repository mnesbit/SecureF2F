package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.api.services.NetworkService
import uk.co.nesbit.network.engine.Layer2Node
import uk.co.nesbit.network.engine.SimNetwork
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RoutingTests {
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
        assertEquals(7, network.messageCount) // Basic session initiation of 4 messages, 1 ratchet kickoff heartbeat, 1 reply heartbeat, 1 routing message
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
    fun `n nodes in a line`() {
        val network = SimNetwork()
        val networks = mutableListOf<NetworkService>()
        val n = 10
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
        for (i in 0 until n + 3) {
            nodes.forEach { it.runStateMachine() }
            network.deliverTillEmpty()
            for (node in nodes) {
                println("${node.networkId} ${node.routeDiscoveryService.knownAddresses.size}")
            }
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
    }
}