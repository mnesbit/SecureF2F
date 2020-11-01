package uk.co.nesbit.network.treeEngine

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.network.api.LinkStatus
import uk.co.nesbit.network.api.active
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
    val clientId: Int,
    val destination: SecureHash
)

data class CloseSessionRequest(
    val clientId: Int?,
    val sessionId: Long?,
    val destination: SecureHash?
) {
    init {
        require(sessionId != null || destination != null) {
            "At least sessionId, or destination must be specified"
        }
    }
}

data class SessionStatusInfo(
    val clientId: Int?,
    val sessionId: Long,
    val destination: SecureHash,
    val status: LinkStatus
)

data class RemoteConnectionAcknowledge(val sessionId: Long, val clientId: Int, val accept: Boolean)

class SendSessionData(val sessionId: Long, val payload: ByteArray)
data class SendSessionDataAck(val sessionId: Long, val success: Boolean)
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
        const val PASSIVE_OPEN_TIMEOUT = 15000L
    }

    private enum class SessionState {
        Created,
        Querying,
        RouteFound,
        PassiveOpen,
        Established,
        Closing,
        Closed
    }

    private class CheckSessions

    private data class SessionInfo(
        val sessionId: Long,
        val destination: SecureHash,
        val passiveOpen: Boolean,
        val creationTime: Instant,
        var clientId: Int?,
        var sender: ActorRef?,
    ) {
        var routeFound: Boolean = false
        var state: SessionState = SessionState.Created
        var status: LinkStatus? = null
        val windowProcessor = SlidingWindowHelper(sessionId)
    }

    private val owners = mutableSetOf<ActorRef>()
    private var selfAddress: SecureHash? = null
    private val sessions = mutableMapOf<Long, SessionInfo>()
    private val routeRequests = mutableSetOf<SecureHash>()
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
            is ClientDhtResponse -> onPeerAddressQuery(message)
            is ClientReceivedMessage -> onSessionDataReceived(message)
            is OpenSessionRequest -> onOpenSession(message)
            is CloseSessionRequest -> onCloseSession(message)
            is SendSessionData -> onSendSessionData(message)
            is ClientSendResult -> onSendResult(message)
            is RemoteConnectionAcknowledge -> onRemoteConnectionAcknowledge(message)
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
    }

    private fun onSelfAddress(addressInfo: NetworkAddressInfo) {
        selfAddress = addressInfo.identity.id
    }

    private fun onSelfAddressRequest() {
        sender.tell(SelfAddressResponse(selfAddress), self)
    }

    private fun onCheckSessions() {
        val now = clock.instant()
        val sessionItr = sessions.iterator()
        while (sessionItr.hasNext()) {
            val session = sessionItr.next().value
            if (!processSession(session, now)) {
                sessionItr.remove()
            }
        }
        setSessionTimer()
    }

    private fun setSessionTimer() {
        val now = clock.instant()
        var nearest = ACK_INTERVAL_MS
        for (session in sessions.values) {
            if (session.routeFound && !session.windowProcessor.isTerminated()) {
                val deadline = session.windowProcessor.getNearestDeadline(now)
                if (deadline < nearest) {
                    nearest = deadline
                }
            }
        }
        timers.startSingleTimer("CheckSessions", CheckSessions(), nearest.millis())
    }

    private fun sendStatusUpdate(session: SessionInfo, newState: LinkStatus) {
        if (session.status != newState) {
            session.status = newState
            val update = SessionStatusInfo(
                session.clientId,
                session.sessionId,
                session.destination,
                newState
            )
            log().info("Session status signal $update to ${session.sender}")
            if (session.sender == null) {
                for (owner in owners) {
                    owner.tell(update, self)
                }
            } else {
                session.sender!!.tell(update, self)
            }
        }
    }

    private fun sendSessionMessages(session: SessionInfo, now: Instant) {
        val messages = session.windowProcessor.pollForTransmit(now)
        for (message in messages) {
            routingActor.tell(ClientSendMessage(session.destination, message), self)
        }
    }

    private fun processSession(session: SessionInfo, now: Instant): Boolean {
        val prevState = session.state
        if (session.windowProcessor.isTerminated()
            && session.state != SessionState.Closed
        ) {
            session.state = SessionState.Closing
        }
        if (session.state == SessionState.PassiveOpen
            && ChronoUnit.MILLIS.between(session.creationTime, now) >= PASSIVE_OPEN_TIMEOUT
        ) {
            log().warning("Passive open of session ${session.sessionId} not acknowledged by client")
            session.state = SessionState.Closing
        }
        when (session.state) {
            SessionState.Created -> {
                if (session.destination !in routeRequests) {
                    routeRequests += session.destination
                    log().warning("probe for destination ${session.destination}")
                    routingActor.tell(ClientDhtRequest(session.destination, null), self)
                }
                session.state = SessionState.Querying
            }
            SessionState.Querying -> { // wait for reply
                if (session.destination !in routeRequests) {
                    routeRequests += session.destination
                    log().warning("re-probe for destination ${session.destination}")
                    routingActor.tell(ClientDhtRequest(session.destination, null), self)
                }
                session.state = SessionState.Querying
            }
            SessionState.RouteFound -> {
                session.routeFound = true
                if (session.windowProcessor.isEstablished()) {
                    log().info("session link ${session.sessionId} established")
                    session.state = SessionState.Established
                    val newState = if (session.passiveOpen) LinkStatus.LINK_UP_PASSIVE else LinkStatus.LINK_UP_ACTIVE
                    sendStatusUpdate(session, newState)
                    sendSessionMessages(session, now)
                } else {
                    session.state = SessionState.RouteFound
                    sendSessionMessages(session, now)
                }
            }
            SessionState.PassiveOpen -> {
                session.routeFound = true
                if (session.windowProcessor.isEstablished()) {
                    sendStatusUpdate(session, LinkStatus.LINK_UP_PASSIVE)
                    sendSessionMessages(session, now)
                } else {
                    sendSessionMessages(session, now)
                }
                session.state = SessionState.PassiveOpen
            }
            SessionState.Established -> {
                if (session.windowProcessor.getMaxRetransmits() >= 3) {
                    if (session.destination !in routeRequests) {
                        routeRequests += session.destination
                        log().warning("excessive retries re-probe for destination ${session.destination}")
                        routingActor.tell(ClientDhtRequest(session.destination, null), self)
                    }
                    session.state = SessionState.Querying
                } else {
                    session.state = SessionState.Established
                    sendSessionMessages(session, now)
                }
            }
            SessionState.Closing -> {
                log().info("session link ${session.sessionId} closing")
                sendStatusUpdate(session, LinkStatus.LINK_DOWN)
                if (!session.routeFound) {
                    session.state = SessionState.Closed
                } else {
                    if (!session.windowProcessor.isTerminated()) {
                        log().info("closing session link ${session.sessionId}")
                        session.windowProcessor.closeSession(now)
                        sendSessionMessages(session, now)
                    } else {
                        session.state = SessionState.Closed
                    }
                }
            }
            SessionState.Closed -> {
                session.state = SessionState.Closed // terminal state await cleanup
            }
        }
        log().info("process ${session.sessionId} prev state $prevState new state ${session.state}")
        return (session.state != SessionState.Closed)
    }

    private fun onOpenSession(openRequest: OpenSessionRequest) {
        log().info("onOpenSession $openRequest")
        val sessionId = abs(keyService.random.nextLong())
        if (selfAddress == null) {
            sender.tell(
                SessionStatusInfo(
                    openRequest.clientId,
                    sessionId,
                    openRequest.destination,
                    LinkStatus.LINK_DOWN
                ), self
            )
            return
        }
        val existing = sessions.values.firstOrNull {
            it.destination == openRequest.destination && it.clientId == openRequest.clientId
        }
        if (existing != null) {
            log().error("Re-use of client id")
            sender.tell(
                SessionStatusInfo(
                    openRequest.clientId,
                    sessionId,
                    openRequest.destination,
                    LinkStatus.LINK_DOWN
                ), self
            )
            return
        }
        val now = clock.instant()
        val newSession = SessionInfo(
            sessionId,
            openRequest.destination,
            false,
            now,
            openRequest.clientId,
            sender
        )
        sessions[sessionId] = newSession
        if (!processSession(newSession, now)) {
            sessions.remove(sessionId)
        }
        setSessionTimer()
    }

    private fun onCloseSession(request: CloseSessionRequest) {
        log().info("close request $request")
        val session = if (request.sessionId != null) {
            val sessionById = sessions[request.sessionId]
            if (sessionById == null) {
                log().warning("Session not found for close")
                return
            }
            if (request.destination != null) {
                if (sessionById.destination != request.destination) {
                    log().warning("destination of session for close does not match expected")
                    return
                }
                if (sessionById.clientId != request.clientId) {
                    log().warning("clientId of session for close does not match expected")
                    return
                }
            }
            sessionById
        } else {
            val sessionByClientIdAndDestination =
                sessions.values.firstOrNull { it.clientId == request.clientId && it.destination == request.destination }
            if (sessionByClientIdAndDestination == null) {
                log().warning("No session found by clientId and destination to close")
                return
            }
            sessionByClientIdAndDestination
        }
        val now = clock.instant()
        session.state = SessionState.Closing
        if (!processSession(session, now)) {
            sessions.remove(session.sessionId)
        }
        setSessionTimer()
    }

    private fun onRemoteConnectionAcknowledge(ack: RemoteConnectionAcknowledge) {
        log().info("Remote connection ack $ack")
        val session = sessions[ack.sessionId]
        if (session == null) {
            log().error("Session not found ${ack.sessionId} to confirm")
            return
        }
        if (session.sender != null
            || !session.passiveOpen
            || session.state != SessionState.PassiveOpen
        ) {
            log().error("Session not in correct state to confirm $session")
            return
        }
        if (ack.accept) {
            session.sender = sender
            session.clientId = ack.clientId
            session.state = SessionState.RouteFound
        } else {
            session.state = SessionState.Closing
        }
        val now = clock.instant()
        if (!processSession(session, now)) {
            sessions.remove(session.sessionId)
        }
        setSessionTimer()
    }

    private fun onPeerAddressQuery(response: ClientDhtResponse) {
        log().info("Route query for ${response.key} returned status ${response.success}")
        routeRequests -= response.key
        val relevant = sessions.values.filter { it.destination == response.key }
        val now = clock.instant()
        for (session in relevant) {
            if (response.success) {
                if (session.state == SessionState.Querying) {
                    session.state = SessionState.RouteFound
                }
            } else {
                session.state = SessionState.Closing
            }
            if (!processSession(session, now)) {
                sessions.remove(session.sessionId)
            }
        }
        setSessionTimer()
    }

    private fun onSendResult(message: ClientSendResult) {
        log().info("session send result ${message.destination} ${message.sent}")
        if (!message.sent) {
            val now = clock.instant()
            val sessions =
                sessions.values.filter { it.state == SessionState.Established && it.destination == message.destination }
            if (sessions.isNotEmpty()) {
                for (session in sessions) {
                    session.state = SessionState.Querying
                    processSession(session, now)
                }
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
        if (session.status?.active != true) {
            log().warning("Session not open")
            sender.tell(SendSessionDataAck(message.sessionId, false), self)
            return
        }
        if (!session.windowProcessor.sendPacket(message.payload)) {
            log().warning("Session buffer full")
            sender.tell(SendSessionDataAck(message.sessionId, false), self)
            return
        }
        val now = clock.instant()
        if (!processSession(session, now)) {
            sessions.remove(session.sessionId)
        }
        setSessionTimer()
        sender.tell(SendSessionDataAck(message.sessionId, true), self)
    }

    private fun onSessionDataReceived(message: ClientReceivedMessage) {
        log().info("packet from ${message.source}")
        val now = clock.instant()
        val session = sessions.getOrPut(message.sessionMessage.sessionId) {
            val incomingSession = SessionInfo(
                message.sessionMessage.sessionId,
                message.source,
                true,
                now,
                null,
                null
            )
            incomingSession.state = SessionState.PassiveOpen
            log().info("new incoming session created ${message.sessionMessage.sessionId}")
            incomingSession
        }
        session.windowProcessor.processMessage(message.sessionMessage, now)
        if (session.sender != null) {
            val received = session.windowProcessor.pollReceivedPackets()
            for (packet in received) {
                val sessionReceive = ReceiveSessionData(session.sessionId, packet)
                session.sender!!.tell(sessionReceive, self)
            }
        }
        if (!processSession(session, now)) {
            sessions.remove(session.sessionId)
        }
        setSessionTimer()
    }

}