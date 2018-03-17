package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.disposables.Disposable
import io.reactivex.subjects.PublishSubject
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.ratchet.RatchetState
import uk.co.nesbit.crypto.session.InitiatorHelloRequest
import uk.co.nesbit.crypto.session.InitiatorSessionParams
import uk.co.nesbit.crypto.session.ResponderHelloResponse
import uk.co.nesbit.crypto.session.ResponderSessionParams
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.Address
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.routing.Heartbeat
import uk.co.nesbit.network.api.routing.RouteEntry
import uk.co.nesbit.network.api.routing.SignedEntry
import uk.co.nesbit.network.api.routing.VersionedRoute.Companion.NONCE_SIZE
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.LinkReceivedMessage
import uk.co.nesbit.network.api.services.NeighbourReceivedMessage
import uk.co.nesbit.network.api.services.NetworkService
import java.security.KeyPair
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class SecureChannelStateMachine(val linkId: LinkId,
                                         private val fromId: SecureHash,
                                         val networkTarget: Address,
                                         val initiator: Boolean,
                                         private val keyService: KeyService,
                                         private val networkService: NetworkService) : AutoCloseable {
    companion object {
        const val TIMEOUT_TICKS = 4
    }

    enum class ChannelState {
        INIT,
        ERRORED,
        WAIT_FOR_INITIATOR_NONCE,
        WAIT_FOR_RESPONDER_NONCE,
        WAIT_FOR_INITIATOR_HELLO,
        WAIT_FOR_RESPONDER_HELLO,
        WAIT_RATCHET_SYNC,
        SESSION_ACTIVE
    }

    private val lock = ReentrantLock()

    var state: ChannelState = ChannelState.INIT
        private set

    var remoteID: VersionedIdentity? = null
        private set

    var routeEntry: Pair<Int, SignedEntry>? = null
        private set

    private var receiveSubscription: Disposable? = null
    private var timeout: Int? = null
    private var sessionInitKeys: KeyPair? = null
    private var initiatorSessionParams: InitiatorSessionParams? = null
    private var responderSessionParams: ResponderSessionParams? = null
    private var initiatorHelloRequest: InitiatorHelloRequest? = null
    private var responderHelloResponse: ResponderHelloResponse? = null
    private var encryptedChannel: RatchetState? = null
    private var heartbeatSendNonce: ByteArray? = null
    private var heartbeatReceiveNonce: ByteArray? = null
    private val earlyMessages = mutableListOf<ByteArray>()

    private val _onReceive = PublishSubject.create<NeighbourReceivedMessage>()
    val onReceive: Observable<NeighbourReceivedMessage>
        get() = _onReceive

    init {
        receiveSubscription = networkService.onReceive.filter { it.linkId == linkId }.subscribe({ onReceived(it) }, { setError() })
    }

    override fun close() {
        lock.withLock {
            state = ChannelState.ERRORED
            receiveSubscription?.dispose()
            receiveSubscription = null
            _onReceive.onComplete()
            earlyMessages.clear()
            sessionInitKeys = null
            initiatorSessionParams = null
            responderSessionParams = null
            initiatorHelloRequest = null
            responderHelloResponse = null
            encryptedChannel = null
            remoteID = null
            routeEntry = null
            heartbeatSendNonce = null
            heartbeatReceiveNonce = null
        }
    }

    fun runStateMachine(): ChannelState {
        lock.withLock {
            val prevState = state
            try {
                when (state) {
                    SecureChannelStateMachine.ChannelState.INIT -> runInit()
                    SecureChannelStateMachine.ChannelState.ERRORED -> {
                        //Terminal state nothing to do
                    }
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_RESPONDER_NONCE,
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_INITIATOR_NONCE,
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_RESPONDER_HELLO,
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_INITIATOR_HELLO,
                    SecureChannelStateMachine.ChannelState.WAIT_RATCHET_SYNC -> {
                        // All these states are clocked by received messages, or a timeout to error
                        runWaitTimeout()
                    }
                    SecureChannelStateMachine.ChannelState.SESSION_ACTIVE -> {
                        runWaitTimeout()
                        sendHeartbeat()
                    }
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                setError()
            }
            if (prevState != state) {
                println("$initiator state $state")
            }
            return state
        }
    }

    private fun onReceived(msg: LinkReceivedMessage) {
        if (msg.linkId != linkId) {
            setError()
            return
        }
        var processedMessage: NeighbourReceivedMessage? = null
        lock.withLock {
            val prevState = state
            try {
                when (state) {
                    SecureChannelStateMachine.ChannelState.INIT -> {
                        runInit()
                        onReceived(msg)
                    }
                    SecureChannelStateMachine.ChannelState.ERRORED -> {
                        // Terminal state nothing to do/discard message
                    }
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_INITIATOR_NONCE -> {
                        processInitiatorParams(msg)
                    }
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_RESPONDER_NONCE -> {
                        processResponderParams(msg)
                    }
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_INITIATOR_HELLO -> {
                        processInitiatorHello(msg)
                    }
                    SecureChannelStateMachine.ChannelState.WAIT_FOR_RESPONDER_HELLO -> {
                        processResponderHello(msg)
                    }
                    SecureChannelStateMachine.ChannelState.WAIT_RATCHET_SYNC -> {
                        processFirstSessionMessage(msg)
                    }
                    SecureChannelStateMachine.ChannelState.SESSION_ACTIVE -> {
                        processedMessage = processSessionMessage(msg)
                    }
                }
            } catch (ex: Exception) {
                ex.printStackTrace()
                setError()
            }
            if (prevState != state) {
                println("$initiator state $state")
            }
        }
        if (processedMessage != null) {
            _onReceive.onNext(processedMessage!!) // forward outside of state machine lock in case of reply sends
        }
    }

    private fun runInit() {
        if (initiator) {
            val (keys, initiatorNonce) = InitiatorSessionParams.createInitiatorSession(keyService.random)
            initiatorSessionParams = initiatorNonce
            sessionInitKeys = keys
            networkService.send(linkId, initiatorNonce.serialize())
            state = ChannelState.WAIT_FOR_RESPONDER_NONCE
        } else {
            state = ChannelState.WAIT_FOR_INITIATOR_NONCE
        }
        timeout = TIMEOUT_TICKS
    }

    private fun processInitiatorParams(msg: LinkReceivedMessage) {
        try {
            val initiatorSession = InitiatorSessionParams.deserialize(msg.msg)
            initiatorSession.verify()
            initiatorSessionParams = initiatorSession
        } catch (ex: Exception) {
            setError()
            return
        }
        val (keys, responderParams) = ResponderSessionParams.createResponderSession(initiatorSessionParams!!, keyService.random)
        responderSessionParams = responderParams
        sessionInitKeys = keys
        networkService.send(linkId, responderParams.serialize())
        state = ChannelState.WAIT_FOR_INITIATOR_HELLO
        timeout = TIMEOUT_TICKS
    }

    private fun processResponderParams(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) || (sessionInitKeys == null)) {
            setError()
            return
        }
        val responderSession = ResponderSessionParams.deserialize(msg.msg)
        responderSession.verify(initiatorSessionParams!!)
        responderSessionParams = responderSession
        val initiatorIdentity = keyService.getVersion(fromId)
        val initiatorHello = InitiatorHelloRequest.createHelloRequest(initiatorSessionParams!!,
                responderSessionParams!!,
                sessionInitKeys!!,
                initiatorIdentity,
                { id, data -> keyService.sign(id, data) })
        networkService.send(linkId, initiatorHello.serialize())
        initiatorHelloRequest = initiatorHello
        state = ChannelState.WAIT_FOR_RESPONDER_HELLO
        timeout = TIMEOUT_TICKS
    }

    private fun processInitiatorHello(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) ||
                (sessionInitKeys == null) ||
                (responderSessionParams == null)) {
            setError()
            return
        }
        val initiatorHello = InitiatorHelloRequest.deserialize(msg.msg)
        remoteID = initiatorHello.verify(initiatorSessionParams!!, responderSessionParams!!, sessionInitKeys!!)
        initiatorHelloRequest = initiatorHello
        val responderIdentity = keyService.getVersion(fromId)
        val responderHello = ResponderHelloResponse.createHelloResponse(initiatorSessionParams!!,
                responderSessionParams!!,
                initiatorHelloRequest!!,
                sessionInitKeys!!,
                responderIdentity,
                { id, data -> keyService.sign(id, data) })
        networkService.send(linkId, responderHello.serialize())
        responderHelloResponse = responderHello
        encryptedChannel = RatchetState.ratchetInitForSession(initiatorSessionParams!!,
                responderSessionParams!!,
                sessionInitKeys!!,
                keyService.random)
        heartbeatReceiveNonce = SecureHash.secureHash(concatByteArrays(initiatorSessionParams!!.serialize(),
                responderSessionParams!!.serialize(),
                initiatorHelloRequest!!.serialize(),
                responderSessionParams!!.serialize())).bytes.copyOf(NONCE_SIZE)
        state = ChannelState.WAIT_RATCHET_SYNC
        timeout = TIMEOUT_TICKS
    }

    private fun processResponderHello(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) ||
                (sessionInitKeys == null) ||
                (responderSessionParams == null) ||
                (initiatorHelloRequest == null)) {
            setError()
            return
        }
        val responderHello = ResponderHelloResponse.deserialize(msg.msg)
        remoteID = responderHello.verify(initiatorSessionParams!!, responderSessionParams!!, initiatorHelloRequest!!, sessionInitKeys!!)
        responderHelloResponse = responderHello
        encryptedChannel = RatchetState.ratchetInitForSession(initiatorSessionParams!!,
                responderSessionParams!!,
                sessionInitKeys!!,
                keyService.random)
        heartbeatSendNonce = SecureHash.secureHash(concatByteArrays(initiatorSessionParams!!.serialize(),
                responderSessionParams!!.serialize(),
                initiatorHelloRequest!!.serialize(),
                responderSessionParams!!.serialize())).bytes.copyOf(NONCE_SIZE)
        sendHeartbeat()
        state = ChannelState.WAIT_RATCHET_SYNC
        timeout = TIMEOUT_TICKS
    }

    private fun processFirstSessionMessage(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) ||
                (sessionInitKeys == null) ||
                (responderSessionParams == null) ||
                (initiatorHelloRequest == null) ||
                (responderHelloResponse == null) ||
                (encryptedChannel == null)) {
            setError()
            return
        }
        val firstMessage = encryptedChannel!!.decryptMessage(msg.msg, null)
        if (!processHeartbeat(firstMessage)) {
            earlyMessages += firstMessage // re-ordering might put a message ahead of the heartbeat
            return
        }
        sendHeartbeat()
        initiatorSessionParams = null
        sessionInitKeys = null
        responderSessionParams = null
        initiatorHelloRequest = null
        responderHelloResponse = null
        state = ChannelState.SESSION_ACTIVE
        timeout = TIMEOUT_TICKS
        if (earlyMessages.isNotEmpty()) {
            val neighbourAddress = SphinxAddress(remoteID!!.identity)
            for (message in earlyMessages) {
                _onReceive.onNext(NeighbourReceivedMessage(neighbourAddress, message))
            }
            earlyMessages.clear()
        }
    }

    private fun processSessionMessage(msg: LinkReceivedMessage): NeighbourReceivedMessage? {
        if ((encryptedChannel == null)
                || (remoteID == null)) {
            setError()
            return null
        }
        val decrypted = encryptedChannel!!.decryptMessage(msg.msg, null)
        if (processHeartbeat(decrypted)) return null
        val neighbourAddress = SphinxAddress(remoteID!!.identity)
        return NeighbourReceivedMessage(neighbourAddress, decrypted)
    }

    private fun sendHeartbeat() {
        if ((encryptedChannel == null)
                || (remoteID == null)) {
            setError()
            return
        }
        if (heartbeatSendNonce == null) {
            return
        }
        val heartbeat = Heartbeat.createHeartbeat(heartbeatSendNonce!!, remoteID!!, keyService, fromId)
        heartbeatReceiveNonce = heartbeat.nextExpectedNonce
        heartbeatSendNonce = null
        val heartbeatMessage = encryptedChannel!!.encryptMessage(heartbeat.serialize(), null)
        networkService.send(linkId, heartbeatMessage)
    }

    private fun processHeartbeat(decrypted: ByteArray): Boolean {
        if (heartbeatReceiveNonce != null) {
            val heartbeat = Heartbeat.tryDeserialize(decrypted)
            if (heartbeat != null) { // Possible heartbeat
                val localIdentity = keyService.getVersion(fromId)
                try {
                    remoteID = heartbeat.verify(heartbeatReceiveNonce!!, localIdentity, remoteID!!)
                    routeEntry = Pair(localIdentity.currentVersion.version,
                            SignedEntry(RouteEntry(heartbeatReceiveNonce!!, remoteID!!),
                                    heartbeat.versionedRouteSignature))
                    heartbeatSendNonce = heartbeat.nextExpectedNonce
                    heartbeatReceiveNonce = null
                    timeout = TIMEOUT_TICKS
                    return true
                } catch (ex: Exception) {
                    // Pass along as message
                    println("Heartbeat verify failed")
                }
            }
        }
        return false
    }

    private fun setError() {
        Exception().printStackTrace()
        println("$initiator Error")
        close()
    }

    private fun runWaitTimeout() {
        val time = timeout
        if (time != null) {
            val newTimeout = time - 1
            if (newTimeout <= 0) {
                timeout = null
                setError()
            } else {
                timeout = newTimeout
            }
        }
    }

    fun send(msg: ByteArray) {
        val encryptedMsg = lock.withLock {
            if ((encryptedChannel == null)
                    || (remoteID == null)) {
                setError()
                return
            }
            encryptedChannel!!.encryptMessage(msg, null)
        }
        try {
            networkService.send(linkId, encryptedMsg)
        } catch (ex: Exception) {
            setError()
            return
        }
    }
}