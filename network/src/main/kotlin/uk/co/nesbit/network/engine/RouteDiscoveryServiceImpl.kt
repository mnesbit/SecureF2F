package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.disposables.Disposable
import io.reactivex.subjects.PublishSubject
import org.bouncycastle.util.Arrays
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.routing.RouteTable
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.api.routing.Routes
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.NeighbourDiscoveryService
import uk.co.nesbit.network.api.services.NeighbourReceivedMessage
import uk.co.nesbit.network.api.services.RouteDiscoveryService
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class RouteDiscoveryServiceImpl(private val neighbourDiscoveryService: NeighbourDiscoveryService, private val keyService: KeyService) : RouteDiscoveryService, AutoCloseable {
    private val sphinxEncoder = Sphinx(keyService.random)
    private val receiveSubscription: Disposable
    private val linkChangeSubscription: Disposable
    private val knownRoutes = mutableListOf<Routes>()
    private val adjacencyGraph = mutableMapOf<Address, List<Address>>()
    private val lock = ReentrantLock()
    override val knownAddresses = mutableSetOf<Address>()
    private val knownIds = mutableMapOf<SecureHash, SphinxAddress>()
    private var neighbourIndex: Int = 0

    private val _onReceive = PublishSubject.create<RoutedMessage>()
    override val onReceive: Observable<RoutedMessage>
        get() = _onReceive

    init {
        receiveSubscription = neighbourDiscoveryService.onReceive.subscribe { processReceivedMessage(it) }
        linkChangeSubscription = neighbourDiscoveryService.onLinkStatusChange.subscribe { processLinkStatusChange() }
    }


    override fun close() {
        linkChangeSubscription.dispose()
        receiveSubscription.dispose()
    }

    override fun send(route: List<Address>, msg: RoutedMessage) {
        require(route.all { it is SphinxAddress }) { "Only able to route Sphinx addresses" }
        require(route.all { it in knownAddresses }) { "Only able to route to known Sphinx addresses" }
        val target = (route.last() as SphinxAddress)
        if (target.id == neighbourDiscoveryService.networkAddress.id) { // reflect self addressed message
            _onReceive.onNext(msg)
            return
        }
        val addressPath = route.map { (it as SphinxAddress).identity }.toList()
        val firstLink = neighbourDiscoveryService.findLinkTo(route.first())
        require(firstLink != null) { "Don't know link to first target" }
        val sendableMessage = sphinxEncoder.makeMessage(addressPath, msg.serialize())
        neighbourDiscoveryService.send(firstLink!!, sendableMessage.messageBytes)
    }

    private fun processLinkStatusChange() {
        lock.withLock {
            refreshLocalRoutes()
            recalculateGraph()
        }
    }

    private fun processReceivedMessage(msg: NeighbourReceivedMessage) {
        val messageResult = sphinxEncoder.processMessage(msg.msg,
                neighbourDiscoveryService.networkAddress.id,
                { remotePubKey -> keyService.getSharedDHSecret(neighbourDiscoveryService.networkAddress.id, remotePubKey) })
        if (messageResult.valid) {
            if (messageResult.finalPayload != null) {
                val routedMessage = try {
                    RoutedMessage.deserialize(messageResult.finalPayload!!)
                } catch (ex: Exception) {
                    println("Bad message")
                    return
                }
                if (Arrays.constantTimeAreEqual(routedMessage.payloadSchemaId, RouteTable.schemaFingerprint)) {
                    processRouteTableMessage(routedMessage)
                } else {
                    _onReceive.onNext(routedMessage)
                }
            } else if (messageResult.forwardMessage != null) {
                val replyAddress = knownIds[messageResult.nextNode!!]
                if (replyAddress != null) {
                    val link = neighbourDiscoveryService.findLinkTo(replyAddress)
                    if (link != null) {
                        neighbourDiscoveryService.send(link, messageResult.forwardMessage!!.messageBytes)
                        return
                    }
                }
                println("Dropping packet! Don't know next address ${messageResult.nextNode}")
            }
        } else {
            println("Bad message received")
        }
    }

    private fun processRouteTableMessage(routedMessage: RoutedMessage) {
        val routes = try {
            RouteTable.deserialize(routedMessage.payload)
        } catch (ex: Exception) {
            println("Bad RouteTable")
            return
        }
        lock.withLock {
            mergeRouteTable(routes)
            recalculateGraph()
            if (routes.replyTo != null && knownIds.containsKey(routes.replyTo)) {
                val replyAddress = knownIds[routes.replyTo]!!
                val replyPath = findRandomRouteTo(replyAddress)
                if (replyPath != null) {
                    val routeTable = RouteTable(knownRoutes, null)
                    send(replyPath, RoutedMessage.createRoutedMessage(neighbourDiscoveryService.networkAddress, routeTable))
                }
            }
        }
    }

    private fun mergeRouteTable(routes: RouteTable) {
        for (route in routes.allRoutes) {
            val existingRouteIndex = knownRoutes.indexOfFirst { it.from.id == route.from.id }
            if (existingRouteIndex == -1) {
                knownRoutes += route
            } else {
                val existingRoute = knownRoutes[existingRouteIndex]
                if (existingRoute.from.currentVersion.version < route.from.currentVersion.version) {
                    knownRoutes[existingRouteIndex] = route
                } else if (existingRoute.from.currentVersion.version == route.from.currentVersion.version
                        && (existingRoute.entries.size <= route.entries.size)) {
                    knownRoutes[existingRouteIndex] = route
                }
            }
        }
    }

    override fun findRandomRouteTo(destination: Address): List<Address>? {
        fun findPathR(prefix: List<Address>, target: Address, depth: Int): List<Address>? {
            val start = prefix.last()
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
                if (sample !in prefix) { // don't go back to ourselves
                    val route = findPathR(prefix + sample, target, depth - 1)
                    if (route != null) {
                        return listOf(start) + route
                    }
                }
            }
            return null
        }
        return lock.withLock {
            findPathR(listOf(neighbourDiscoveryService.networkAddress), destination, sphinxEncoder.maxRouteLength)?.drop(1) // discard starting element
        }
    }

    override fun runStateMachine() {
        lock.withLock {
            refreshLocalRoutes()
            recalculateGraph()
        }
        val neighbors = neighbourDiscoveryService.knownNeighbours.toList()
        if (neighbors.isNotEmpty()) {
            neighbourIndex = neighbourIndex.rem(neighbors.size)
            val target = neighbors[neighbourIndex]
            ++neighbourIndex
            if (target in knownAddresses) {
                val path = listOf(target)
                val routeTable = RouteTable(knownRoutes, neighbourDiscoveryService.networkAddress.id)
                send(path, RoutedMessage.createRoutedMessage(neighbourDiscoveryService.networkAddress, routeTable))
            }
        }
    }

    private fun refreshLocalRoutes() {
        // Update our local info
        knownRoutes.removeIf { it.from.id == neighbourDiscoveryService.networkAddress.id }
        val localRoutes = neighbourDiscoveryService.routes
        if (localRoutes != null) {
            knownRoutes += localRoutes
        }
    }

    private fun recalculateGraph() {
        // Clear and rebuild graph info
        knownAddresses.clear()
        adjacencyGraph.clear()
        knownIds.clear()
        for (routes in knownRoutes) {
            val fromAddress = SphinxAddress(routes.from.identity)
            knownAddresses += fromAddress
            knownIds[fromAddress.id] = fromAddress
            val adjacencyList = mutableListOf<Address>()
            adjacencyGraph[fromAddress] = adjacencyList
            for (entry in routes.entries) {
                val toAddress = SphinxAddress(entry.to.identity)
                knownAddresses += toAddress
                knownIds[toAddress.id] = toAddress
                adjacencyList += toAddress
            }
        }
        // don't include self in knownAddresses
        knownAddresses.remove(neighbourDiscoveryService.networkAddress)
    }
}