package uk.co.nesbit.network.engine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import org.bouncycastle.util.Arrays
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.BloomFilter
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.sphinx.Sphinx
import uk.co.nesbit.crypto.sphinx.SphinxPublicIdentity
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.routing.RouteEntry
import uk.co.nesbit.network.api.routing.RouteTable
import uk.co.nesbit.network.api.routing.RoutedMessage
import uk.co.nesbit.network.api.routing.Routes
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.millis
import java.util.*

class LocalRoutesUpdate(val localAddress: SphinxPublicIdentity, val routes: Routes?)

class RouteDiscoveryActor(private val keyService: KeyService, private val neighbourLinkActor: ActorRef) :
    AbstractActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(keyService: KeyService, neighbourLinkActor: ActorRef): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return Props.create(javaClass.enclosingClass, keyService, neighbourLinkActor)
        }

        const val ROUTE_DISCOVERY_INTERVAL_MS = 5000L
    }

    private class Tick

    private var round = 0
    private val owners = mutableSetOf<ActorRef>()
    private val sphinxEncoder = Sphinx(keyService.random)
    private var networkAddress: SphinxPublicIdentity? = null
    private var localRoutes: Routes? = null
    private val routes = mutableMapOf<SecureHash, Routes>()
    private val knownAddresses = mutableSetOf<SphinxPublicIdentity>()
    private val knownIds = mutableMapOf<SecureHash, SphinxPublicIdentity>()

    override fun preStart() {
        super.preStart()
        //log().info("Starting RouteDiscoveryActor")
        neighbourLinkActor.tell(WatchRequest(), self)
        timers.startPeriodicTimer(
            "routeTick",
            Tick(),
            ROUTE_DISCOVERY_INTERVAL_MS.millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped RouteDiscoveryActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart RouteDiscoveryActor")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(WatchRequest::class.java) { onWatchRequest() }
            .match(Tick::class.java) { onTick() }
            .match(LocalRoutesUpdate::class.java, ::onLocalRoutesUpdate)
            .match(NeighbourReceivedMessage::class.java, ::onNeighbourReceivedMessage)
            .build()

    private fun onWatchRequest() {
        //log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onTick() {
        //log().info("onTick")
        ++round
        log().info("round $round knownRoutes ${routes.size} knownAddresses ${knownAddresses.size}")
        if (knownAddresses.isNotEmpty()) {
            val randomTarget = findRandomTarget()
            if (randomTarget != null) {
                sendRouteTable(randomTarget, null)
            }
        }
    }

    private fun sendRouteTable(target: SphinxPublicIdentity, respondTo: RouteTable?) {
        val path = findRandomRouteTo(target)
        if (!path.isNullOrEmpty()) {
            val selectedRoutes = mutableSetOf<Routes>()
            val knownAddresses = BloomFilter(routes.size, 0.02, keyService.random.nextInt())
            var clean = (respondTo != null)
            selectedRoutes += routes[networkAddress!!.id]!!
            for (step in path) {
                if (routes.containsKey(step.id)) {
                    selectedRoutes += routes[step.id]!!
                }
            }
            for (route in routes.values) {
                knownAddresses.add(route.from.serialize())
                if (respondTo != null) {
                    if (!respondTo.knownSources.possiblyContains(route.from.serialize())) {
                        selectedRoutes += route
                        clean = false
                    }
                }
            }
            if (respondTo != null) {
                for (externalRoute in respondTo.fullRoutes) {
                    val knownRoute = routes[externalRoute.from.id]!!
                    if ((externalRoute.from.currentVersion.version < knownRoute.from.currentVersion.version)
                        || (externalRoute.from.currentVersion.version < knownRoute.from.currentVersion.version
                                && externalRoute.entries.size < knownRoute.entries.size)
                    ) {

                        selectedRoutes += knownRoute
                        clean = false
                    }
                }
            }

            val replyTo = if (clean) null else networkAddress!!.id
            val routeTable = RouteTable(selectedRoutes.toList(), knownAddresses, replyTo)
            send(path, RoutedMessage.createRoutedMessage(SphinxAddress(networkAddress!!), routeTable))
        }
    }

    private fun onLocalRoutesUpdate(routeUpdate: LocalRoutesUpdate) {
        //log().info("onLocalRoutesUpdate $routeUpdate")
        networkAddress = routeUpdate.localAddress
        localRoutes = routeUpdate.routes
        if (routeUpdate.routes != null) {
            routes[routeUpdate.localAddress.id] = routeUpdate.routes
        } else {
            routes.remove(routeUpdate.localAddress.id)
        }
        recalculateAddresses()
    }

    private fun recalculateAddresses() {
        knownAddresses.clear()
        knownIds.clear()
        for (route in routes.values) {
            val fromAddress = route.from.identity
            knownAddresses += fromAddress
            knownIds[fromAddress.id] = fromAddress
            for (entry in route.entries) {
                val toAddress = entry.to.identity
                knownAddresses += toAddress
                knownIds[toAddress.id] = toAddress
            }
        }
    }

    private fun onNeighbourReceivedMessage(msg: NeighbourReceivedMessage) {
        val messageResult = sphinxEncoder.processMessage(
            msg.msg,
            networkAddress!!.id
        ) { remotePubKey -> keyService.getSharedDHSecret(networkAddress!!.id, remotePubKey) }
        if (messageResult.valid) {
            if (messageResult.finalPayload != null) {
                val routedMessage = try {
                    RoutedMessage.deserialize(messageResult.finalPayload!!)
                } catch (ex: Exception) {
                    log().error("Bad message")
                    return
                }
                if (Arrays.constantTimeAreEqual(routedMessage.payloadSchemaId, RouteTable.schemaFingerprint)) {
                    processRouteTableMessage(routedMessage)
                } else {
                    for (owner in owners) {
                        owner.tell(routedMessage, self)
                    }
                }
            } else if (messageResult.forwardMessage != null) {
                val nextAddress = knownIds[messageResult.nextNode!!]
                if (nextAddress != null) {
                    neighbourLinkActor.tell(
                        NeighbourSendMessage(
                            nextAddress,
                            messageResult.forwardMessage!!.messageBytes
                        ), self
                    )
                    return
                }
                log().warning("Dropping packet! Don't know next address ${messageResult.nextNode}")
            }
        } else {
            log().error("Bad message received")
        }
    }

    private fun processRouteTableMessage(routedMessage: RoutedMessage) {
        val routeTable = try {
            val msg = RouteTable.deserialize(routedMessage.payload)
            msg.verify()
            msg
        } catch (ex: Exception) {
            log().error("Bad RouteTable")
            return
        }

        for (routeEntry in routeTable.fullRoutes) {
            val fromAddress = routeEntry.from.identity.id
            val currentEntry = routes[fromAddress]
            if (currentEntry == null
                || (currentEntry.from.currentVersion.version < routeEntry.from.currentVersion.version)
                || ((currentEntry.from.currentVersion.version == routeEntry.from.currentVersion.version)
                        && (currentEntry.entries.size < routeEntry.entries.size))
            ) {
                routes[fromAddress] = routeEntry
            }
        }
        recalculateAddresses()
        if (routeTable.replyTo != null) {
            val replyAddress = knownIds[routeTable.replyTo]
            if (replyAddress != null) {
                sendRouteTable(replyAddress, routeTable)
            }
        }
    }

    private fun findRandomTarget(): SphinxPublicIdentity? {
        if (knownAddresses.isEmpty()) return null
        val knownAddresses = knownAddresses.toList()
        return knownAddresses[keyService.random.nextInt(knownAddresses.size)]
    }

    private fun findRandomRouteTo(destination: SphinxPublicIdentity): List<SphinxPublicIdentity>? {
        val rand = Random(keyService.random.nextLong())
        fun randomIterator(nextIndex: Int, scrambledSequence: IntArray): Int {
            // Randomising iterator
            val swapIndex = nextIndex + rand.nextInt(scrambledSequence.size - nextIndex)
            val currentIndex = scrambledSequence[swapIndex]
            scrambledSequence[swapIndex] = scrambledSequence[nextIndex]
            scrambledSequence[nextIndex] = currentIndex
            return currentIndex
        }

        if (destination == networkAddress) {
            return emptyList()
        }
        val maxDepth = sphinxEncoder.maxRouteLength
        var depth = 0
        val iterationStack = IntArray(maxDepth)
        val randomStack = Array(maxDepth) { IntArray(0) }
        val path = Array(maxDepth) { emptyList<RouteEntry>() }
        val neighbourRoutes = routes[networkAddress!!.id] ?: return null
        path[depth] = neighbourRoutes.entries
        if (path[depth].isEmpty()) {
            return null
        }
        iterationStack[depth] = 0
        randomStack[depth] = IntArray(path[depth].size) { it }

        while (true) {
            val currentIndex = randomIterator(iterationStack[depth], randomStack[depth])
            val nextNode = path[depth][currentIndex].to.identity
            if (nextNode == destination) {
                val output = mutableListOf<SphinxPublicIdentity>()
                for (i in 0..depth) {
                    output += path[i][randomStack[i][iterationStack[i]]].to.identity
                }
                return output
            }
            val nextRoute = routes[nextNode.id]
            var inPrefix = false
            if (nextRoute != null) {
                for (i in 0..depth) {
                    if (path[i] == nextRoute.entries) {
                        inPrefix = true
                        break
                    }
                }
            }
            if (depth < maxDepth - 1 && nextRoute != null && nextRoute.entries.isNotEmpty() && !inPrefix) {
                ++depth
                path[depth] = nextRoute.entries
                iterationStack[depth] = 0
                randomStack[depth] = IntArray(path[depth].size) { it }
            } else {
                while (depth >= 0) {
                    if (iterationStack[depth] < randomStack[depth].size - 1) {
                        ++iterationStack[depth]
                        break
                    } else {
                        --depth
                    }
                }
                if (depth < 0) {
                    return null
                }
            }
        }
    }

    private fun send(route: List<SphinxPublicIdentity>, msg: RoutedMessage) {
        require(route.all { it in knownAddresses }) { "Only able to route to known Sphinx knownAddresses" }
        val target = route.last()
        if (target.id == networkAddress!!.id) { // reflect self addressed message
            for (owner in owners) {
                owner.tell(msg, self)
            }
            return
        }
        val sendableMessage = sphinxEncoder.makeMessage(route, msg.serialize())
        neighbourLinkActor.tell(NeighbourSendMessage(route.first(), sendableMessage.messageBytes), self)
    }
}