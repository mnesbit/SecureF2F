package uk.co.nesbit.network.engineOld

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
import uk.co.nesbit.utils.ThreadSafeState

class RouteDiscoveryServiceImpl(private val neighbourDiscoveryService: NeighbourDiscoveryService, private val keyService: KeyService) : RouteDiscoveryService, AutoCloseable {
    private val sphinxEncoder = Sphinx(keyService.random)
    private val networkAddress: SphinxAddress = neighbourDiscoveryService.networkAddress
    private val receiveSubscription: Disposable
    private val linkChangeSubscription: Disposable

    private class RouteState {
        val knownRoutes = mutableListOf<Routes>()
        val adjacencyGraph = mutableMapOf<Address, List<Address>>()
        val knownAddresses = mutableSetOf<Address>()
        val knownIds = mutableMapOf<SecureHash, SphinxAddress>()
        var validRoutes: Boolean = false
        var neighbourIndex: Int = 0
    }

    private val state = ThreadSafeState(RouteState())

    private val _onReceive = PublishSubject.create<RoutedMessage>()
    override val onReceive: Observable<RoutedMessage>
        get() = _onReceive

    init {
        receiveSubscription = neighbourDiscoveryService.onReceive.subscribe { processReceivedMessage(it) }
        linkChangeSubscription = neighbourDiscoveryService.onLinkStatusChange.subscribe { processLinkStatusChange() }
    }

    override val knownAddresses: Set<Address>
        get() = state.locked { HashSet(knownAddresses) }


    override fun close() {
        linkChangeSubscription.dispose()
        receiveSubscription.dispose()
    }

    override fun send(route: List<Address>, msg: RoutedMessage) {
        require(route.all { it is SphinxAddress }) { "Only able to route Sphinx addresses" }
        require(route.all { it in knownAddresses }) { "Only able to route to known Sphinx addresses" }
        val target = (route.last() as SphinxAddress)
        if (target.id == networkAddress.id) { // reflect self addressed message
            _onReceive.onNext(msg)
            return
        }
        val addressPath = route.map { (it as SphinxAddress).identity }.toList()
        val firstLink = neighbourDiscoveryService.findLinkTo(route.first())
        require(firstLink != null) { "Don't know link to first target" }
        val sendableMessage = sphinxEncoder.makeMessage(addressPath, msg.serialize())
        neighbourDiscoveryService.send(firstLink, sendableMessage.messageBytes)
    }

    private fun processLinkStatusChange() {
        recalculateGraph()
    }

    private fun processReceivedMessage(msg: NeighbourReceivedMessage) {
        val messageResult = sphinxEncoder.processMessage(msg.msg,
                networkAddress.id,
                { remotePubKey -> keyService.getSharedDHSecret(networkAddress.id, remotePubKey) })
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
                val replyAddress = state.locked { knownIds[messageResult.nextNode!!] }
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
        val routeTable = try {
            val msg = RouteTable.deserialize(routedMessage.payload)
            msg.verify()
            msg
        } catch (ex: Exception) {
            println("Bad RouteTable")
            return
        }

        mergeRouteTable(routeTable)
        recalculateGraph()

        val (path, routes) = state.locked {
            if (routeTable.replyTo == null || !validRoutes) {
                return@locked Pair(null, null)
            }
            val replyAddress = knownIds[routeTable.replyTo] ?: return@locked Pair(null, null)
            val replyPath = findRandomRouteTo(replyAddress) ?: return@locked Pair(null, null)
            Pair(replyPath, ArrayList(knownRoutes))
        }
        if (path != null) {
            val routeReplyTable = RouteTable(routes!!, null)
            send(path, RoutedMessage.createRoutedMessage(networkAddress, routeReplyTable))
        }
    }

    private fun mergeRouteTable(routes: RouteTable) {
        state.locked {
            for (route in routes.allRoutes) {
                val existingRouteIndex = knownRoutes.indexOfFirst { it.from.id == route.from.id }
                if (existingRouteIndex == -1) {
                    knownRoutes += route
                } else {
                    val existingRoute = knownRoutes[existingRouteIndex]
                    if (existingRoute.from.currentVersion.version < route.from.currentVersion.version) {
                        knownRoutes[existingRouteIndex] = route
                    } else if (existingRoute.from.currentVersion.version == route.from.currentVersion.version
                            && (existingRoute.entries.size < route.entries.size)) {
                        knownRoutes[existingRouteIndex] = route
                    }
                }
            }
        }
    }

    override fun findRandomRouteTo(destination: Address): List<Address>? {
        return state.locked {
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

            findPathR(listOf(networkAddress), destination, sphinxEncoder.maxRouteLength)?.drop(1) // discard starting element
        }
    }

    override fun runStateMachine() {
        recalculateGraph()

        val neighbors = neighbourDiscoveryService.knownNeighbours.toList()
        val (path, routes) = state.locked {
            if (!validRoutes || neighbors.isEmpty()) {
                return@locked Pair(null, null)
            }
            val allAddresses = knownAddresses.toList()
            val randomTarget = allAddresses[keyService.random.nextInt(allAddresses.size)]
            val randomPath = findRandomRouteTo(randomTarget)
            if (randomPath != null) {
                return@locked Pair(randomPath, ArrayList(knownRoutes))
            }
            neighbourIndex = neighbourIndex.rem(neighbors.size)
            val target = neighbors[neighbourIndex]
            ++neighbourIndex
            if (target !in knownAddresses) {
                return@locked Pair(null, null)
            }
            Pair(listOf(target), ArrayList(knownRoutes))
        }
        if (path != null) {
            val routeTable = RouteTable(routes!!, networkAddress.id)
            send(path, RoutedMessage.createRoutedMessage(networkAddress, routeTable))
        }
    }

    private fun recalculateGraph() {
        val localRoutes = neighbourDiscoveryService.routes
        state.locked {
            validRoutes = false
            // Update our local info
            knownRoutes.removeIf { it.from.id == networkAddress.id }
            if (localRoutes != null) {
                knownRoutes += localRoutes
                validRoutes = true
            }
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
            knownAddresses.remove(networkAddress)
        }
    }
}