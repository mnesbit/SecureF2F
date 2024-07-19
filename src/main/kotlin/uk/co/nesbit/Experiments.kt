package uk.co.nesbit

import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.toByteArray
import uk.co.nesbit.network.api.LinkStatus
import uk.co.nesbit.network.api.active
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.treeEngine.*
import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.ActorSystem
import uk.co.nesbit.simpleactor.ask
import java.time.Duration
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

object Experiments {
    fun createStream(
        simNodes: List<TreeNode>,
        actorSystem: ActorSystem,
        openAttempts: Int,
        messageCount: Int
    ) {
        val random = Random()
        val timeout = Duration.ofSeconds(120L)
        var sourceAddress: SecureHash? = null
        var destAddress: SecureHash? = null
        val sourceIndex = random.nextInt(simNodes.size)
        val sourceName: String = simNodes[sourceIndex].name
        val randomSourceNodes = actorSystem.actorSelection("SimpleActor://f2f/$sourceName/session")
        while (randomSourceNodes.resolve().isEmpty()) {
            Thread.sleep(100L)
        }
        val destIndex = random.nextInt(simNodes.size)
        val destName: String = simNodes[destIndex].name
        val randomDestNodes = actorSystem.actorSelection("SimpleActor://f2f/$destName/session")
        while (randomDestNodes.resolve().isEmpty()) {
            Thread.sleep(100L)
        }
        val randomSourceNode = randomSourceNodes.resolve().single()
        val randomDestNode = randomDestNodes.resolve().single()
        val churnActor = actorSystem.actorSelection("SimpleActor://f2f/churn").resolve().firstOrNull()
        if (churnActor != null) {
            churnActor.tell(Protect(simNodes[sourceIndex].rootNodeActor))
            churnActor.tell(Protect(simNodes[destIndex].rootNodeActor))
        }
        while (true) {
            Thread.sleep(1000L)
            val sourceFut = randomSourceNode.ask<SelfAddressResponse>(SelfAddressRequest())
            try {
                val sourceResult = sourceFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
                sourceAddress = sourceResult.address
            } catch (ex: TimeoutException) {
            }
            if (sourceAddress == null) {
                continue
            }
            val destFut = randomDestNode.ask<SelfAddressResponse>(SelfAddressRequest())
            try {
                val destResult = destFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
                destAddress = destResult.address
            } catch (ex: TimeoutException) {
            }
            if (destAddress == null) {
                continue
            }
            break
        }
        println("using $sourceName $sourceAddress -> $destName $destAddress")
        val closeFut = CompletableFuture<Boolean>()
        val sink = actorSystem.createMessageSink { self, msg, sender ->
            if (msg is SessionStatusInfo) {
                println("New session $msg")
                sender.tell(RemoteConnectionAcknowledge(msg.sessionId, 999, true), self)
                if (msg.status == LinkStatus.LINK_DOWN) {
                    closeFut.complete(true)
                }
            } else if (msg is ReceiveSessionData) {
                println("Received ${msg.payload.toString(Charsets.UTF_8)} from ${msg.sessionId}")
            } else {
                println("unknown message type $msg")
            }
        }
        randomDestNode.tell(WatchRequest(), sink)
        var queryNo = 0
        var sessionId: Long
        var attempts = 0
        while (true) {
            if (attempts >= openAttempts) {
                println("failed to open session after $attempts attempts")
                return
            }
            Thread.sleep(1000L)
            val sessionSourceNode = actorSystem.actorSelection("SimpleActor://f2f/$sourceName/session")
            println("Send open query")
            val openFut =
                sessionSourceNode.resolve().single()
                    .ask<SessionStatusInfo>(OpenSessionRequest(queryNo++, destAddress!!))
            try {
                val destResult = openFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
                println("result $destResult ${destResult.sessionId}")
                if (destResult.status.active) {
                    sessionId = destResult.sessionId
                    break
                }
            } catch (ex: TimeoutException) {
            }
            ++attempts
        }
        println("Session $sessionId opened")

        var packetNo = 0
        while (packetNo < messageCount) {
            val sessionSourceNode =
                actorSystem.actorSelection("SimpleActor://f2f/$sourceName/session").resolve().single()
            println("Send data query $packetNo")
            val sendFut = sessionSourceNode.ask<SendSessionDataAck>(
                SendSessionData(sessionId, "hello$packetNo".toByteArray(Charsets.UTF_8))
            )
            try {
                val destResult = sendFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
                println("result $destResult ${destResult.sessionId} success ${destResult.success} busy ${destResult.busy}")
                if (!destResult.success) {
                    println("Session closed terminating early")
                    break
                }
                if (!destResult.busy) {
                    packetNo++
                } else {
                    Thread.sleep(100L)
                }
            } catch (ex: TimeoutException) {
            }
        }
        val sessionNode = actorSystem.actorSelection("SimpleActor://f2f/$sourceName/session")
        sessionNode.tell(CloseSessionRequest(null, sessionId, null), ActorRef.noSender())
        closeFut.get()
        sink.close()
    }

    fun pollDht(
        simNodes: List<TreeNode>,
        actorSystem: ActorSystem,
        successes: Int
    ) {
        val random = Random()
        var round = 0
        val timeout = Duration.ofSeconds(120L)
        var sinceFailure = 0
        val stored = mutableListOf<Pair<SecureHash, ByteArray>>()
        while (sinceFailure < successes) {
            Thread.sleep(5000L)
            ++round
            var failed = false
            var randomPutNode: ActorRef? = null
            while (randomPutNode == null) {
                val putTarget = simNodes[random.nextInt(simNodes.size)].name
                randomPutNode =
                    actorSystem.actorSelection("SimpleActor://f2f/$putTarget/route").resolve().singleOrNull()
            }
            val data = round.toByteArray()
            val key = SecureHash.secureHash(data)
            val putRequest = ClientDhtRequest(key, data)
            println("send put $round $key to ${randomPutNode.path}")
            val startPut = System.nanoTime()
            val putFut = randomPutNode.ask<ClientDhtResponse>(putRequest)
            try {
                val putResult = putFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
                val diff = ((System.nanoTime() - startPut) / 1000L).toDouble() / 1000.0
                println("put result $putResult in $diff ms ${if (putResult.success) "OK" else "FAIL"}")
                if (!putResult.success) failed = true
                if (putResult.success) {
                    stored += Pair(key, data)
                }
            } catch (ex: TimeoutException) {
                println("put query $round timed out FAIL")
                failed = true
            }

            var randomGetNode: ActorRef? = null
            while (randomGetNode == null) {
                val getTarget = simNodes[random.nextInt(simNodes.size)].name
                randomGetNode = actorSystem.actorSelection("SimpleActor://f2f/$getTarget/route").resolve().firstOrNull()
            }
            val (readKey, readData) = if (stored.isEmpty()) {
                Pair(key, data)
            } else {
                stored[random.nextInt(stored.size)]
            }
            val getRequest = ClientDhtRequest(readKey, null)
            println("send get $round $readKey to ${randomGetNode.path}")
            val startGet = System.nanoTime()
            val getFut = randomGetNode.ask<ClientDhtResponse>(getRequest)
            try {
                val getResult = getFut.get(timeout.toMillis(), TimeUnit.MILLISECONDS)
                val diff = ((System.nanoTime() - startGet) / 1000L).toDouble() / 1000.0
                println("get result $getResult in $diff ms ${if (getResult.success && readData.contentEquals(getResult.data)) "OK" else "FAIL"}")
                if (!getResult.success || !readData.contentEquals(getResult.data)) {
                    failed = true
                    stored.removeIf { it.first == readKey }
                } else if (stored.size > 5) {
                    stored.removeIf { it.first == readKey }
                }
            } catch (ex: TimeoutException) {
                println("get query $round timed out FAIL")
                failed = true
            }
            if (failed) {
                sinceFailure = 0
            } else {
                ++sinceFailure
            }
            println("$sinceFailure rounds since DHT failure")
        }
    }
}