package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.tree.NetworkAddressInfo
import uk.co.nesbit.network.mocknet.WatchRequest
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import uk.co.nesbit.utils.printHexBinary
import java.time.Clock
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.math.abs

class SelfAddressRequest
data class SelfAddressResponse(val address: SecureHash?)
data class OpenSessionRequest(
    val destination: SecureHash,
    val clientId: Int
)

data class OpenSessionResponse(
    val destination: SecureHash,
    val clientId: Int,
    val sessionId: Long,
    val success: Boolean
)

data class IncomingSession(
    val source: SecureHash,
    val sessionId: Long
)

class SendSessionData(val sessionId: Long, val payload: ByteArray)
class SendSessionDataAck(val sessionId: Long, val success: Boolean)
class ReceiveSessionData(val sessionId: Long, val payload: ByteArray)

class SessionActor(
    private val keyService: KeyService,
    private val routingActor: ActorRef
) :
    UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            keyService: KeyService,
            routingActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, keyService, routingActor)
        }

        const val ACK_INTERVAL_MS = 5000L
        const val CONNECT_TIMEOUT = 10000L
    }

    private class SessionInfo(
        val sessionId: Long,
        val clientId: Int,
        val destination: SecureHash,
        val sender: ActorRef,
        val opened: Instant,
        var lastUpdate: Instant,
        var open: Boolean = false
    ) {
        var queryOpen: Boolean = false
        val windowProcessor = SlidingWindowHelper(sessionId)
    }

    private class CheckSessions

    private val owners = mutableSetOf<ActorRef>()
    private var selfAddress: SecureHash? = null
    private val sessions = mutableMapOf<Long, SessionInfo>()
    private val clock: Clock = Clock.systemUTC()

    override fun preStart() {
        super.preStart()
        //log().info("Starting SessionActor")
        routingActor.tell(WatchRequest(), self)
        timers.startSingleTimer(
            "CheckSessions",
            CheckSessions(),
            keyService.random.nextInt(ACK_INTERVAL_MS.toInt()).toLong().millis()
        )
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped SessionActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().warning("Restart SessionActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is WatchRequest -> onWatchRequest()
            is Terminated -> onDeath(message)
            is NetworkAddressInfo -> onSelfAddress(message)
            is SelfAddressRequest -> onSelfAddressRequest()
            is CheckSessions -> onCheckSessions()
            is ClientDhtResponse -> onInitialQuery(message)
            is ClientReceivedMessage -> onClientReceivedMessage(message)
            is OpenSessionRequest -> onOpenSession(message)
            is SendSessionData -> onSendSessionData(message)
            is ClientSendResult -> onSendResult(message)
            else -> throw IllegalArgumentException("Unknown message type ${message.javaClass.name}")
        }
    }

    private fun onWatchRequest() {
        log().info("WatchRequest from $sender")
        if (sender !in owners) {
            owners += sender
            context.watch(sender)
        }
    }

    private fun onDeath(message: Terminated) {
        log().info("actor died ${message.actor}")
        owners -= message.actor
        val sessionsItr = sessions.iterator()
        while (sessionsItr.hasNext()) {
            val session = sessionsItr.next()
            if (session.value.sender == message.actor) {
                sessionsItr.remove()
            }
        }
    }

    private fun onSelfAddress(addressInfo: NetworkAddressInfo) {
        selfAddress = addressInfo.identity.id
    }

    private fun onSelfAddressRequest() {
        sender.tell(SelfAddressResponse(selfAddress), self)
    }

    private fun onCheckSessions() {
        //log().info("check sessions")
        val now = clock.instant()
        val failedSessions = mutableListOf<SessionInfo>()
        for (session in sessions.values) {
            if (session.open &&
                !session.windowProcessor.isEstablished() &&
                ChronoUnit.MILLIS.between(session.opened, now) >= CONNECT_TIMEOUT
            ) {
                session.open = false
                failedSessions += session
                continue
            }
            sendSessionMessages(session)
            if (session.open &&
                session.windowProcessor.getMaxRetransmits() >= 3 &&
                !session.queryOpen
            ) {
                session.queryOpen = true
                log().warning("too many retransmits re-probe for destination ${session.destination}")
                routingActor.tell(ClientDhtRequest(session.destination, null), self)
            }
        }
        for (session in failedSessions) {
            sessions.remove(session.sessionId)
            session.sender.tell(
                OpenSessionResponse(session.destination, session.clientId, session.sessionId, false),
                self
            )
        }
        setSessionTimer()
    }

    private fun setSessionTimer() {
        val now = clock.instant()
        var nearest = ACK_INTERVAL_MS
        for (session in sessions.values) {
            if (session.open) {
                val deadline = session.windowProcessor.getNearestDeadline(now)
                if (deadline < nearest) {
                    nearest = deadline
                }
            }
        }
        timers.startSingleTimer("CheckSessions", CheckSessions(), ACK_INTERVAL_MS.millis())
    }

    private fun onClientReceivedMessage(message: ClientReceivedMessage) {
        log().info("packet from ${message.source}")
        val session = sessions.getOrPut(message.sessionMessage.sessionId) {
            val now = clock.instant()
            val incomingSession = SessionInfo(
                message.sessionMessage.sessionId,
                -1,
                message.source,
                self,
                now,
                now,
                true
            )
            val signal = IncomingSession(message.source, incomingSession.sessionId)
            log().info("new incoming session created $signal")
            for (owner in owners) {
                owner.tell(signal, self)
            }
            incomingSession
        }
        if (session.open) {
            if (!session.windowProcessor.isEstablished()
                && session.sender != self
            ) {
                session.sender.tell(
                    OpenSessionResponse(session.destination, session.clientId, session.sessionId, true),
                    self
                )
            }
            session.windowProcessor.processMessage(message.sessionMessage, clock.instant())
            sendSessionMessages(session)
            val received = session.windowProcessor.pollReceivedPackets()
            for (packet in received) {
                val sessionReceive = ReceiveSessionData(session.sessionId, packet)
                if (session.sender == self) {
                    for (owner in owners) {
                        owner.tell(sessionReceive, self)
                    }
                } else {
                    session.sender.tell(sessionReceive, self)
                }
            }
            setSessionTimer()
        }
    }

    private fun onOpenSession(openRequest: OpenSessionRequest) {
        log().info("onOpenSession $openRequest")
        val sessionId = abs(keyService.random.nextLong())
        if (selfAddress == null) {
            sender.tell(OpenSessionResponse(openRequest.destination, openRequest.clientId, sessionId, false), self)
            return
        }
        val existing =
            sessions.values.firstOrNull { it.destination == openRequest.destination && it.clientId == openRequest.clientId }
        if (existing != null) {
            log().error("Re-use of client id")
            sender.tell(
                OpenSessionResponse(openRequest.destination, openRequest.clientId, existing.sessionId, false),
                self
            )
            return
        }
        val newSession = SessionInfo(
            sessionId,
            openRequest.clientId,
            openRequest.destination,
            sender,
            clock.instant(),
            Instant.ofEpochMilli(0L)
        )
        sessions[sessionId] = newSession
        newSession.queryOpen = true
        routingActor.tell(ClientDhtRequest(openRequest.destination, null), self)
    }

    private fun onInitialQuery(response: ClientDhtResponse) {
        log().info("Initial query for ${response.key} returned status ${response.success}")
        val relevant = sessions.values.filter { it.destination == response.key }
        if (response.success) {
            for (session in relevant) {
                session.queryOpen = false
                if (!session.open) {
                    session.open = true
                    sendSessionMessages(session)
                }
            }
        } else {
            for (session in relevant) {
                session.queryOpen = false
                if (!session.open) {
                    sessions.remove(session.sessionId)
                    session.sender.tell(
                        OpenSessionResponse(session.destination, session.clientId, session.sessionId, false),
                        self
                    )
                }
            }
        }
        setSessionTimer()
    }

    private fun sendSessionMessages(session: SessionInfo) {
        if (!session.open) {
            return
        }
        val now = clock.instant()
        val messages = session.windowProcessor.pollForTransmit(now)
        session.lastUpdate = now
        for (message in messages) {
            routingActor.tell(ClientSendMessage(session.destination, message), self)
        }
    }

    private fun onSendResult(message: ClientSendResult) {
        log().info("session send result ${message.destination} ${message.sent}")
        if (!message.sent) {
            val sessions = sessions.values.filter { it.open && it.destination == message.destination }
            if (sessions.isNotEmpty()) {
                for (session in sessions) {
                    session.queryOpen = true
                }
                log().warning("re-probe for destination ${message.destination}")
                routingActor.tell(ClientDhtRequest(message.destination, null), self)
            }
        }
    }

    private fun onSendSessionData(message: SendSessionData) {
        log().info("data request ${message.sessionId} ${message.payload.printHexBinary()}")
        val session = sessions[message.sessionId]
        if (session == null) {
            log().error("Session not found")
            sender.tell(SendSessionDataAck(message.sessionId, false), self)
            return
        }
        if (!session.open) {
            log().warning("Session not open")
            sender.tell(SendSessionDataAck(message.sessionId, false), self)
            return
        }
        if (!session.windowProcessor.sendPacket(message.payload)) {
            log().warning("Session buffer full")
            sender.tell(SendSessionDataAck(message.sessionId, false), self)
            return
        }
        sendSessionMessages(session)
        setSessionTimer()
        sender.tell(SendSessionDataAck(message.sessionId, true), self)
    }

}