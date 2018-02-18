package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.engine.Node
import uk.co.nesbit.network.engine.SimNetwork

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
    }
}