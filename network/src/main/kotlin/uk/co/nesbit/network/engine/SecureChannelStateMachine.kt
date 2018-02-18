package uk.co.nesbit.network.engine

import io.reactivex.Observable
import io.reactivex.disposables.Disposable
import io.reactivex.subjects.PublishSubject
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.ratchet.RatchetState
import uk.co.nesbit.crypto.session.InitiatorHelloRequest
import uk.co.nesbit.crypto.session.InitiatorSessionParams
import uk.co.nesbit.crypto.session.ResponderHelloResponse
import uk.co.nesbit.crypto.session.ResponderSessionParams
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.SphinxAddress
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.api.services.LinkReceivedMessage
import uk.co.nesbit.network.api.services.NeighbourReceivedMessage
import uk.co.nesbit.network.api.services.NetworkService
import java.security.KeyPair
import java.util.*
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal class SecureChannelStateMachine(val linkId: LinkId,
                                         private val initiator: Boolean,
                                         private val keyService: KeyService,
                                         private val networkService: NetworkService) : AutoCloseable {
    companion object {
        const val TIMEOUT_TICKS = 5
        val helloBytes = "Hello".toByteArray(Charsets.UTF_8)
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
        get
        private set

    var remoteID: VersionedIdentity? = null
        get
        private set

    private var receiveSubscription: Disposable? = null
    private var timeout: Int? = null
    private var sessionInitKeys: KeyPair? = null
    private var initiatorSessionParams: InitiatorSessionParams? = null
    private var responderSessionParams: ResponderSessionParams? = null
    private var initiatorHelloRequest: InitiatorHelloRequest? = null
    private var responderHelloResponse: ResponderHelloResponse? = null
    private var encryptedChannel: RatchetState? = null
    private var currentVersion: VersionedIdentity? = null

    fun runStateMachine(): ChannelState {
        lock.withLock {
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
                    sendHeartbeat()
                }
            }
            return state
        }
    }

    private fun runInit() {
        receiveSubscription = networkService.onReceive.filter { it.linkId == linkId }.subscribe({ onReceived(it) }, { setError() })
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

    override fun close() {
        receiveSubscription?.dispose()
        receiveSubscription = null
        sessionInitKeys = null
        initiatorSessionParams = null
        responderSessionParams = null
        initiatorHelloRequest = null
        responderHelloResponse = null
        encryptedChannel = null
        currentVersion = null
        remoteID = null
    }

    private fun onReceived(msg: LinkReceivedMessage) {
        if (msg.linkId != linkId) {
            setError()
            return
        }
        lock.withLock {
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
                    processSessionMessage(msg)
                }
            }
        }
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
        try {
            val responderSession = ResponderSessionParams.deserialize(msg.msg)
            responderSession.verify(initiatorSessionParams!!)
            responderSessionParams = responderSession
        } catch (ex: Exception) {
            setError()
            return
        }
        currentVersion = keyService.getVersion(keyService.networkId)
        val initiatorHello = InitiatorHelloRequest.createHelloRequest(initiatorSessionParams!!,
                responderSessionParams!!,
                sessionInitKeys!!,
                currentVersion!!,
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
        try {
            val initiatorHello = InitiatorHelloRequest.deserialize(msg.msg)
            remoteID = initiatorHello.verify(initiatorSessionParams!!, responderSessionParams!!, sessionInitKeys!!)
            initiatorHelloRequest = initiatorHello
        } catch (ex: Exception) {
            setError()
            return
        }
        currentVersion = keyService.getVersion(keyService.networkId)
        val responderHello = ResponderHelloResponse.createHelloResponse(initiatorSessionParams!!,
                responderSessionParams!!,
                initiatorHelloRequest!!,
                sessionInitKeys!!,
                currentVersion!!,
                { id, data -> keyService.sign(id, data) })
        networkService.send(linkId, responderHello.serialize())
        responderHelloResponse = responderHello
        encryptedChannel = RatchetState.ratchetInitForSession(initiatorSessionParams!!,
                responderSessionParams!!,
                sessionInitKeys!!,
                keyService.random)
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
        try {
            val responderHello = ResponderHelloResponse.deserialize(msg.msg)
            remoteID = responderHello.verify(initiatorSessionParams!!, responderSessionParams!!, initiatorHelloRequest!!, sessionInitKeys!!)
            responderHelloResponse = responderHello
        } catch (ex: Exception) {
            setError()
            return
        }
        encryptedChannel = RatchetState.ratchetInitForSession(initiatorSessionParams!!,
                responderSessionParams!!,
                sessionInitKeys!!,
                keyService.random)
        val firstSessionMessage = encryptedChannel!!.encryptMessage(helloBytes,
                concatByteArrays(initiatorSessionParams!!.serialize(),
                        responderSessionParams!!.serialize(),
                        initiatorHelloRequest!!.serialize(),
                        responderSessionParams!!.serialize()))
        networkService.send(linkId, firstSessionMessage)
        initiatorSessionParams = null
        sessionInitKeys = null
        responderSessionParams = null
        initiatorHelloRequest = null
        responderHelloResponse = null
        state = ChannelState.SESSION_ACTIVE
        timeout = null
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
        try {
            val firstMessage = encryptedChannel!!.decryptMessage(msg.msg,
                    concatByteArrays(initiatorSessionParams!!.serialize(),
                            responderSessionParams!!.serialize(),
                            initiatorHelloRequest!!.serialize(),
                            responderSessionParams!!.serialize()))
            if (!Arrays.equals(helloBytes, firstMessage)) {
                setError()
                return
            }
        } catch (ex: Exception) {
            setError()
            return
        }
        initiatorSessionParams = null
        sessionInitKeys = null
        responderSessionParams = null
        initiatorHelloRequest = null
        responderHelloResponse = null
        state = ChannelState.SESSION_ACTIVE
        timeout = null
    }

    private fun processSessionMessage(msg: LinkReceivedMessage) {
        if ((encryptedChannel == null)
                || (remoteID == null)) {
            setError()
            return
        }
        val decrypted = try {
            encryptedChannel!!.decryptMessage(msg.msg, null)
        } catch (ex: Exception) {
            setError()
            return
        }
        if (Arrays.equals(decrypted.copyOf(helloBytes.size), helloBytes)) { // Possible heartbeat
            val restOfHeartbeat = decrypted.copyOfRange(helloBytes.size, decrypted.size)
            try {
                val versionedIdentity = VersionedIdentity.deserialize(restOfHeartbeat)
                if (versionedIdentity.identity != remoteID!!.identity) {
                    setError()
                    return
                }
                if (versionedIdentity.currentVersion.version < remoteID!!.currentVersion.version) {
                    setError()
                    return
                }
                remoteID = versionedIdentity
                return // swallow heartbeat
            } catch (ex: Exception) {
                // Ignore an assume not a heartbeat
            }
        }
        val neighbourAddress = SphinxAddress(remoteID!!.identity)
        _onReceive.onNext(NeighbourReceivedMessage(neighbourAddress, decrypted))
    }

    private fun sendHeartbeat() {
        if ((encryptedChannel == null)
                || (remoteID == null)) {
            setError()
            return
        }

        currentVersion = keyService.getVersion(keyService.networkId)
        val helloPacket = concatByteArrays(helloBytes, currentVersion!!.serialize())
        val heartbeatMessage = encryptedChannel!!.encryptMessage(helloPacket, null)
        networkService.send(linkId, heartbeatMessage)
    }

    private fun setError() {
        lock.withLock {
            state = ChannelState.ERRORED
            close()
        }
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
        if ((encryptedChannel == null)
                || (remoteID == null)) {
            setError()
            return
        }
        val encryptedMsg = encryptedChannel!!.encryptMessage(msg, null)
        networkService.send(linkId, encryptedMsg)
    }

    private val _onReceive = PublishSubject.create<NeighbourReceivedMessage>()
    val onReceive: Observable<NeighbourReceivedMessage>
        get() = _onReceive

}