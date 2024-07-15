package uk.co.nesbit

import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.NetworkAddress
import uk.co.nesbit.utils.resourceAsString
import java.util.*

object TopologyBuilder {
    fun createNetwork(shape: NetworkGenerator, mindegree: Int, N: Int): Map<Address, Set<Address>> {
        return when (shape) {
            NetworkGenerator.MinimumDegree -> makeRandomNetwork(mindegree, N)
            NetworkGenerator.BarabasiAlbert -> makeBarabasiAlbertNetwork(mindegree, N)
            NetworkGenerator.Linear -> makeLinearNetwork(N)
            NetworkGenerator.ASNetwork -> makeASNetwork()
        }
    }

    private fun makeLinearNetwork(N: Int): Map<Address, Set<Address>> {
        val simNetwork = mutableMapOf<Address, Set<Address>>()
        for (i in (1..N)) {
            val links = mutableSetOf<Address>()
            if (i > 1) {
                links += NetworkAddress(i - 1)
            }
            if (i < N) {
                links += NetworkAddress(i + 1)
            }
            simNetwork[NetworkAddress(i)] = links
        }
        return simNetwork
    }

    private fun makeBarabasiAlbertNetwork(minDegree: Int, N: Int): Map<Address, Set<Address>> {
        val rand = Random()
        val simNetwork = mutableMapOf<Address, MutableSet<Address>>()
        val allEdges = mutableListOf<Pair<Address, Address>>()
        for (nodeAddress in (1 until minDegree)) {
            val currentNode = NetworkAddress(nodeAddress)
            val currentLinks = simNetwork.getOrPut(currentNode) { mutableSetOf() }
            for (otherAddress in (nodeAddress + 1..minDegree)) {
                val otherNode = NetworkAddress(otherAddress)
                val otherLinks = simNetwork.getOrPut(otherNode) { mutableSetOf() }
                currentLinks += otherNode
                otherLinks += currentNode
                allEdges += Pair(currentNode, otherNode)
            }
        }
        for (nodeAddress in (minDegree + 1..N)) {
            val currentNode = NetworkAddress(nodeAddress)
            val currentLinks = simNetwork.getOrPut(currentNode) { mutableSetOf() }
            while (currentLinks.size < minDegree) {
                val randEdge = allEdges[rand.nextInt(allEdges.size)]
                val otherNode = if (rand.nextBoolean()) randEdge.first else randEdge.second
                if (otherNode in currentLinks) continue
                val otherLinks = simNetwork.getOrPut(otherNode) { mutableSetOf() }
                currentLinks += otherNode
                otherLinks += currentNode
            }
            for (otherNode in currentLinks) {
                allEdges += Pair(currentNode, otherNode)
            }
        }
        return simNetwork
    }

    private fun makeRandomNetwork(minDegree: Int, N: Int): Map<Address, Set<Address>> {
        // Note this won't be uniform over regular graphs, but that code gets messy
        val rand = Random()
        val simNetwork = mutableMapOf<Address, MutableSet<Address>>()

        for (nodeAddress in (1..N)) {
            val currentNode = NetworkAddress(nodeAddress)
            val currentLinks = simNetwork.getOrPut(currentNode) { mutableSetOf() }
            while (currentLinks.size < minDegree) {
                val otherNode = NetworkAddress(1 + rand.nextInt(N))
                if (otherNode != currentNode) {
                    val otherLinks = simNetwork.getOrPut(otherNode) { mutableSetOf() }
                    currentLinks += otherNode
                    otherLinks += currentNode
                }
            }
        }

        return simNetwork
    }

    private fun makeASNetwork(): Map<Address, Set<Address>> {
        val classLoader = ClassLoader.getSystemClassLoader()
        //From https://snap.stanford.edu/data/as-733.html
        val networkInfoFile = resourceAsString("as20000102.txt", classLoader)!!
        val lines = networkInfoFile.lines()
        val network = mutableMapOf<Address, MutableSet<Address>>()
        for (line in lines) {
            if (line.startsWith('#')) continue
            val splits = line.split(' ', ',', '\t')
            if (splits.size < 2) continue
            val left = splits[0].toInt()
            val right = splits[1].toInt()
            if (left == right) continue
            val leftNode = NetworkAddress(left)
            val rightNode = NetworkAddress(right)
            val linksLeft = network.getOrPut(leftNode) { mutableSetOf() }
            linksLeft += rightNode
            val linksRight = network.getOrPut(rightNode) { mutableSetOf() }
            linksRight += leftNode
        }
        return network
    }
}