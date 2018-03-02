package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.disposables.Disposable
import io.reactivex.subjects.PublishSubject
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.HashAddress
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.routing.RouteTable
import uk.co.nesbit.network.api.routing.Routes
import uk.co.nesbit.network.api.services.*
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class RouteDiscoveryServiceImpl(private val neighbourDiscoveryService: NeighbourDiscoveryService, private val keyService: KeyService) : RouteDiscoveryService, AutoCloseable {
    private val sphinxEncoder = Sphinx(keyService.random)
    private val receiveSubscription: Disposable
    private val knownRoutes = mutableListOf<Routes>()
    private val adjacencyGraph = mutableMapOf<Address, List<Address>>()
    private val lock = ReentrantLock()
    override val knownAddresses = mutableSetOf<Address>()

    private val _onReceive = PublishSubject.create<RouteReceivedMessage>()
    override val onReceive: Observable<RouteReceivedMessage>
        get() = _onReceive

    init {
        receiveSubscription = neighbourDiscoveryService.onReceive.subscribe { processReceivedMessage(it) }
    }

    override fun close() {
        receiveSubscription.dispose()
    }

    override fun send(route: List<Address>, msg: ByteArray) {
        require(route.all { it is SphinxAddress }) { "Only able to route Sphinx addresses" }
        require(route.all { it in knownAddresses }) { "Only able to route to known Sphinx addresses" }
        val target = (route.last() as SphinxAddress)
        if (target.id == neighbourDiscoveryService.networkAddress.id) { // reflect self addressed message
            _onReceive.onNext(RouteReceivedMessage(target, msg))
            return
        }
        val addressPath = route.map { (it as SphinxAddress).identity }.toList()
        val firstLink = neighbourDiscoveryService.findLinkTo(route.first())
        require(firstLink != null) { "Don't know link to first target" }
        val sendableMessage = sphinxEncoder.makeMessage(addressPath, msg)
        neighbourDiscoveryService.send(firstLink!!, sendableMessage.messageBytes)
    }

    private fun processReceivedMessage(msg: NeighbourReceivedMessage) {
        val messageResult = sphinxEncoder.processMessage(msg.msg,
                neighbourDiscoveryService.networkAddress.id,
                { remotePubKey -> keyService.getSharedDHSecret(neighbourDiscoveryService.networkAddress.id, remotePubKey) })
        if (messageResult.valid) {
            if (messageResult.finalPayload != null) {
                //_onReceive.onNext(RouteReceivedMessage())
                try {
                    val routes = RouteTable.deserialize(messageResult.finalPayload!!)
                    for (route in routes.allRoutes) {
                        route.verify()
                    }
                } catch (ex: Exception) {

                }
            } else if (messageResult.forwardMessage != null) {
                val link = neighbourDiscoveryService.findLinkTo(HashAddress(messageResult.nextNode!!))
                if (link == null) {
                    println("Dropping packet! Don't know next address ${messageResult.nextNode}")
                } else {
                    neighbourDiscoveryService.send(link, messageResult.forwardMessage!!.messageBytes)
                }
            }
        } else {
            println("Bad message received")
        }
    }

    override fun findRandomRouteTo(destination: Address): List<Address>? {
        fun findPathR(start: Address, target: Address, depth: Int): List<Address>? {
            if (start == target) return listOf(target)
            if (depth == 0) return null
            val adjList = adjacencyGraph[start] ?: return null
            val scrambled = adjList.toMutableList()
            val n = scrambled.size
            for (i in 0 until n) {
                // Randomising iterator
                val swapIndex = i + keyService.random.nextInt(n - i)
                val sample = scrambled[swapIndex]
                scrambled[swapIndex] = scrambled[i]
                scrambled[i] = sample
                val route = findPathR(sample, target, depth - 1)
                if (route != null) {
                    return listOf(start) + route
                }
            }
            return null
        }
        return lock.withLock {
            findPathR(neighbourDiscoveryService.networkAddress, destination, sphinxEncoder.maxRouteLength)?.drop(1) // discard starting element
        }
    }

    override fun runStateMachine() {
        val randomTarget = lock.withLock {
            // Update our local info
            knownRoutes.removeIf { it.from.id == neighbourDiscoveryService.networkAddress.id }
            val localRoutes = neighbourDiscoveryService.routes
            if (localRoutes != null) {
                knownRoutes += localRoutes
            }
            // Clear and rebuild graph info
            knownAddresses.clear()
            adjacencyGraph.clear()
            for (routes in knownRoutes) {
                val fromAddress = SphinxAddress(routes.from.identity)
                knownAddresses += fromAddress
                val adjacencyList = mutableListOf<Address>()
                adjacencyGraph[fromAddress] = adjacencyList
                for (entry in routes.entries) {
                    val toAddress = SphinxAddress(entry.to.identity)
                    knownAddresses += toAddress
                    adjacencyList += toAddress
                }
            }
            // don't include self in knownAddresses
            knownAddresses.remove(neighbourDiscoveryService.networkAddress)
            if (knownAddresses.isNotEmpty()) {
                // identify gossip target
                val addressList = knownAddresses.toList()
                addressList[keyService.random.nextInt(addressList.size)]
            } else null
        }
        if (randomTarget != null) {
            val path = findRandomRouteTo(randomTarget)
            if (path != null) {
                val routeTable = RouteTable(knownRoutes, neighbourDiscoveryService.networkAddress.id)
                send(path, routeTable.serialize())
            }
        }
    }
}