package uk.co.nesbit.network

import org.junit.Test
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.network.engine.Layer2Node
import uk.co.nesbit.network.engine.SimNetwork

class RoutingTests {
    @Test
    fun `simple two node network`() {
        val network = SimNetwork()
        val net1 = network.getNetworkService(NetworkAddress(1))
        val net2 = network.getNetworkService(NetworkAddress(2))
        val node1 = Layer2Node(net1)
        val node2 = Layer2Node(net2)
        net1.openLink(net2.networkId)
        for (i in 0 until 100) {
            node1.runStateMachine()
            node2.runStateMachine()
            network.deliverTillEmpty()
        }

    }
}