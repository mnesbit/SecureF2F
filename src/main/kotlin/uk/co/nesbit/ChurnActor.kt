package uk.co.nesbit

import org.apache.commons.math3.distribution.LogNormalDistribution
import org.apache.commons.math3.distribution.PoissonDistribution
import org.apache.commons.math3.random.MersenneTwister
import uk.co.nesbit.network.api.NetworkConfiguration
import uk.co.nesbit.network.treeEngine.ConfigQuery
import uk.co.nesbit.network.treeEngine.TreeNode
import uk.co.nesbit.simpleactor.*
import java.time.Clock
import java.time.Instant
import kotlin.math.sqrt

data class Protect(val actor: ActorRef)
data class Unprotect(val actor: ActorRef)

class ChurnActor(
    arrivalRate: Double,
    private val minSession: Int,
    sessionDurationMu: Double,
    sessionDurationSigma: Double
) : AbstractActor() {
    companion object {
        @JvmStatic
        fun getProps(
            arrivalRate: Double,
            minSession: Int,
            sessionDurationMu: Double,
            sessionDurationSigma: Double
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(
                javaClass.enclosingClass,
                arrivalRate,
                minSession,
                sessionDurationMu,
                sessionDurationSigma
            )
        }

        const val TICK_INTERVAL = 1000L
    }

    private val knownNodes = mutableMapOf<ActorRef, Pair<Instant, NetworkConfiguration>>()
    private val availableConfigs = mutableListOf<NetworkConfiguration>()
    private val protected = mutableSetOf<ActorRef>()
    private val localRand = MersenneTwister(System.currentTimeMillis())
    private val sessionDistribution = LogNormalDistribution(localRand, sessionDurationMu, sessionDurationSigma)
    private val arrivalDistribution = PoissonDistribution(localRand, arrivalRate, 1.0E-12, 10000000)
    private var round: Int = 0

    private object Tick

    override fun preStart() {
        log().info(
            "session min $minSession mean ${minSession + 1000.0 * sessionDistribution.numericalMean} sd ${
                1000.0 * sqrt(
                    sessionDistribution.numericalVariance
                )
            } arrival ${arrivalDistribution.mean}"
        )
        super.preStart()
        timers.startTimerAtFixedDelay("ChurnTimer", Tick, TICK_INTERVAL.millis(), TICK_INTERVAL.millis())
    }


    override fun onReceive(message: Any) {
        when (message) {
            is Tick -> onTick()
            is Terminated -> onDeath(message)
            is Protect -> onProtect(message)
            is Unprotect -> onUnprotect(message)
            is NetworkConfiguration -> updateKnown(message)
            else -> throw IllegalArgumentException("Unknown message type: ${message.javaClass.name}")
        }
    }

    private fun onTick() {
        ++round
        val now = Clock.systemUTC().instant()
        if ((knownNodes.keys - protected).isEmpty()) {
            val allNodes = context.actorSelection("/*").resolve().toSet()
            val knownItr = knownNodes.iterator()
            while (knownItr.hasNext()) {
                val known = knownItr.next()
                if (known.key !in allNodes) {
                    knownItr.remove()
                    context.unwatch(known.key)
                }
            }
            for (node in allNodes) {
                if (node == self || node.path.name == "Dns") {
                    continue
                }
                if (!knownNodes.containsKey(node)) {
                    context.watch(node)
                    node.tell(ConfigQuery, self)
                }
            }
        }
        terminateExpired(now)
        generateNewArrivals(now)
    }

    private fun terminateExpired(now: Instant) {
        for (known in knownNodes) {
            if (known.value.first < now) {
                log().info("Peer expired ${known.value} total nodes ${knownNodes.size}")
                known.key.tell(Kill, self)
            }
        }
    }

    private fun generateNewArrivals(now: Instant) {
        val newNodes = arrivalDistribution.sample()
        for (i in 0 until newNodes) {
            if (availableConfigs.isEmpty()) break
            val conf = availableConfigs.removeAt(localRand.nextInt(availableConfigs.size))
            val tree = TreeNode(context.system, conf)
            context.watch(tree.rootNodeActor)
            calculateSessionLifetime(now, tree.rootNodeActor, conf)
            log().info("New peer added ${tree.rootNodeActor} total nodes ${knownNodes.size}")
        }
    }

    private fun onDeath(message: Terminated) {
        val info = knownNodes.remove(message.actor)
        if (info != null) {
            availableConfigs += info.second
        }
        log().info("node died ${message.actor} total nodes ${knownNodes.size}")
    }

    private fun updateKnown(nodeAddress: NetworkConfiguration) {
        val now = Clock.systemUTC().instant()
        calculateSessionLifetime(now, sender, nodeAddress)
    }

    private fun calculateSessionLifetime(now: Instant, actor: ActorRef, config: NetworkConfiguration) {
        if (actor in protected) {
            knownNodes[actor] = Pair(now.plusSeconds(86400L), config)
        } else {
            val sessionDuration = minSession.toLong() + (1000.0 * sessionDistribution.sample()).toLong()
            log().info("$actor duration $sessionDuration s")
            knownNodes[actor] = Pair(now.plusSeconds(sessionDuration), config)
        }
    }

    private fun onProtect(message: Protect) {
        protected += message.actor
        message.actor.tell(ConfigQuery, self)
    }

    private fun onUnprotect(message: Unprotect) {
        protected -= message.actor
        val now = Clock.systemUTC().instant()
        val info = knownNodes[message.actor]
        if (info != null) {
            calculateSessionLifetime(now, message.actor, info.second)
        }
    }
}