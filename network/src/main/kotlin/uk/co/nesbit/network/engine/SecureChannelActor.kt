package uk.co.nesbit.network.engine

import akka.actor.ActorRef
import akka.actor.Props
import akka.japi.pf.ReceiveBuilder
import uk.co.nesbit.avro.serialize
import uk.co.nesbit.crypto.SecureHash
import uk.co.nesbit.crypto.concatByteArrays
import uk.co.nesbit.crypto.ratchet.RatchetState
import uk.co.nesbit.crypto.session.InitiatorHelloRequest
import uk.co.nesbit.crypto.session.InitiatorSessionParams
import uk.co.nesbit.crypto.session.ResponderHelloResponse
import uk.co.nesbit.crypto.session.ResponderSessionParams
import uk.co.nesbit.crypto.session.SessionSecretState.Companion.NONCE_SIZE
import uk.co.nesbit.crypto.sphinx.VersionedIdentity
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.LinkReceivedMessage
import uk.co.nesbit.network.api.LinkSendMessage
import uk.co.nesbit.network.api.routing.Heartbeat
import uk.co.nesbit.network.api.routing.RouteEntry
import uk.co.nesbit.network.api.routing.SignedEntry
import uk.co.nesbit.network.api.services.KeyService
import uk.co.nesbit.network.mocknet.CloseRequest
import uk.co.nesbit.network.util.AbstractActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import uk.co.nesbit.network.util.millis
import java.security.KeyPair
import java.time.Clock
import java.time.Duration
import java.time.Instant

class SecureChannelReceivedMessage(val linkId: LinkId, val sourceId: VersionedIdentity, val msg: ByteArray)
class SecureChannelSendMessage(val linkId: LinkId, val msg: ByteArray)

data class SecureChannelRouteUpdate(val linkId: LinkId, val fromId: VersionedIdentity, val routeEntry: SignedEntry)
data class SecureChannelClose(val linkId: LinkId)

class SecureChannelActor(
    val linkId: LinkId,
    private val fromId: SecureHash,
    private val initiator: Boolean,
    private val keyService: KeyService,
    private val networkActor: ActorRef
) : AbstractActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(
            linkId: LinkId,
            fromId: SecureHash,
            initiator: Boolean,
            keyService: KeyService,
            networkActor: ActorRef
        ): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, linkId, fromId, initiator, keyService, networkActor)
        }

        const val HEARTBEAT_INTERVAL_MS = 20000L
        const val HEARTBEAT_TIMEOUT_MS = 4L * HEARTBEAT_INTERVAL_MS
    }

    private class Tick

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

    private var state: ChannelState = ChannelState.INIT
    private var sessionInitKeys: KeyPair? = null
    private var initiatorSessionParams: InitiatorSessionParams? = null
    private var responderSessionParams: ResponderSessionParams? = null
    private var initiatorHelloRequest: InitiatorHelloRequest? = null
    private var responderHelloResponse: ResponderHelloResponse? = null
    private var encryptedChannel: RatchetState? = null
    private var lastSendTime: Instant = Clock.systemUTC().instant()
    private var heartbeatSendIdentity: VersionedIdentity? = null
    private var heartbeatSendNonce: ByteArray? = null
    private var lastReceiveTime: Instant = Clock.systemUTC().instant()
    private var heartbeatReceiveNonce: ByteArray? = null
    private var remoteID: VersionedIdentity? = null

    override fun preStart() {
        super.preStart()
        //log().info("Starting SecureChannelActor $linkId")
        onInit()
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped SecureChannelActor $linkId")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart SecureChannelActor $linkId")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(LinkReceivedMessage::class.java, ::onLinkReceiveMessage)
            .match(SecureChannelSendMessage::class.java, ::onSecureChannelSendMessage)
            .match(Tick::class.java) { onTick() }
            .build()

    private fun onTick() {
        val now = Clock.systemUTC().instant()
        val receiveDelay = Duration.between(lastReceiveTime, now).toMillis()
        if (receiveDelay > HEARTBEAT_TIMEOUT_MS) {
            log().error("Heartbeat timeout after $receiveDelay msec")
            setError()
            return
        }
        if (heartbeatSendNonce != null) {
            val sendDelay = Duration.between(lastSendTime, now).toMillis()
            if (sendDelay > HEARTBEAT_INTERVAL_MS) {
                sendHeartbeat()
            }
        }
    }


    private fun onLinkReceiveMessage(message: LinkReceivedMessage) {
        require(message.linkId == linkId) { "Message received from wrong link $message" }
        val prevState = state
        try {
            when (state) {
                ChannelState.INIT -> {
                    throw IllegalStateException("Should not be in init state!")
                }
                ChannelState.ERRORED -> {
                    //Terminal state nothing to do
                }
                ChannelState.WAIT_FOR_INITIATOR_NONCE -> {
                    processInitiatorParams(message)
                }
                ChannelState.WAIT_FOR_RESPONDER_NONCE -> {
                    processResponderParams(message)
                }
                ChannelState.WAIT_FOR_INITIATOR_HELLO -> {
                    processInitiatorHello(message)
                }
                ChannelState.WAIT_FOR_RESPONDER_HELLO -> {
                    processResponderHello(message)
                }
                ChannelState.WAIT_RATCHET_SYNC -> {
                    processFirstSessionMessage(message)
                }
                ChannelState.SESSION_ACTIVE -> {
                    processSessionMessage(message)
                }
            }
        } catch (ex: Exception) {
            log().error(ex, "Error in SecureChannelActor")
            setError()
        }
        if (prevState != state) {
            updateTimeout() // update handshake timer
            log().info("$initiator state $state")
        }
    }

    private fun close() {
        state = ChannelState.ERRORED
        sessionInitKeys = null
        initiatorSessionParams = null
        responderSessionParams = null
        initiatorHelloRequest = null
        responderHelloResponse = null
        encryptedChannel = null
        networkActor.tell(CloseRequest(linkId), ActorRef.noSender())
        context.parent.tell(SecureChannelClose(linkId), self)
    }

    private fun setError() {
        log().error(Exception(), "$initiator State machine error")
        close()
    }

    private fun onInit() {
        if (initiator) {
            val (keys, initiatorNonce) = InitiatorSessionParams.createInitiatorSession(keyService.random)
            initiatorSessionParams = initiatorNonce
            sessionInitKeys = keys
            networkActor.tell(LinkSendMessage(linkId, initiatorNonce.serialize()), self)
            state = ChannelState.WAIT_FOR_RESPONDER_NONCE
        } else {
            state = ChannelState.WAIT_FOR_INITIATOR_NONCE
        }
        updateTimeout()
        timers.startTimerAtFixedRate("linkHeartbeat", Tick(), HEARTBEAT_INTERVAL_MS.millis())
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
        val (keys, responderParams) = ResponderSessionParams.createResponderSession(
            initiatorSessionParams!!,
            keyService.random
        )
        responderSessionParams = responderParams
        sessionInitKeys = keys
        networkActor.tell(LinkSendMessage(linkId, responderParams.serialize()), self)
        state = ChannelState.WAIT_FOR_INITIATOR_HELLO
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
        val initiatorIdentity = keyService.getVersion(fromId)
        val initiatorHello = InitiatorHelloRequest.createHelloRequest(
            initiatorSessionParams!!,
            responderSessionParams!!,
            sessionInitKeys!!,
            initiatorIdentity
        ) { id, data -> keyService.sign(id, data) }
        networkActor.tell(LinkSendMessage(linkId, initiatorHello.serialize()), self)
        initiatorHelloRequest = initiatorHello
        state = ChannelState.WAIT_FOR_RESPONDER_HELLO
    }

    private fun processResponderHello(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) ||
            (sessionInitKeys == null) ||
            (responderSessionParams == null) ||
            (initiatorHelloRequest == null)
        ) {
            setError()
            return
        }
        val responderHello = ResponderHelloResponse.deserialize(msg.msg)
        remoteID = responderHello.verify(
            initiatorSessionParams!!,
            responderSessionParams!!,
            initiatorHelloRequest!!,
            sessionInitKeys!!
        )
        responderHelloResponse = responderHello
        encryptedChannel = RatchetState.ratchetInitForSession(
            initiatorSessionParams!!,
            responderSessionParams!!,
            sessionInitKeys!!,
            keyService.random
        )
        heartbeatSendNonce = SecureHash.secureHash(
            concatByteArrays(
                initiatorSessionParams!!.serialize(),
                responderSessionParams!!.serialize(),
                initiatorHelloRequest!!.serialize(),
                responderSessionParams!!.serialize()
            )
        ).bytes.copyOf(NONCE_SIZE)
        sendHeartbeat()
        state = ChannelState.WAIT_RATCHET_SYNC
    }

    private fun processInitiatorHello(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) ||
            (sessionInitKeys == null) ||
            (responderSessionParams == null)
        ) {
            setError()
            return
        }
        val initiatorHello = InitiatorHelloRequest.deserialize(msg.msg)
        remoteID = initiatorHello.verify(initiatorSessionParams!!, responderSessionParams!!, sessionInitKeys!!)
        initiatorHelloRequest = initiatorHello
        val responderIdentity = keyService.getVersion(fromId)
        val responderHello = ResponderHelloResponse.createHelloResponse(
            initiatorSessionParams!!,
            responderSessionParams!!,
            initiatorHelloRequest!!,
            sessionInitKeys!!,
            responderIdentity
        ) { id, data -> keyService.sign(id, data) }
        networkActor.tell(LinkSendMessage(linkId, responderHello.serialize()), self)
        responderHelloResponse = responderHello
        encryptedChannel = RatchetState.ratchetInitForSession(
            initiatorSessionParams!!,
            responderSessionParams!!,
            sessionInitKeys!!,
            keyService.random
        )
        heartbeatSendIdentity = responderIdentity
        heartbeatReceiveNonce = SecureHash.secureHash(
            concatByteArrays(
                initiatorSessionParams!!.serialize(),
                responderSessionParams!!.serialize(),
                initiatorHelloRequest!!.serialize(),
                responderSessionParams!!.serialize()
            )
        ).bytes.copyOf(NONCE_SIZE)
        state = ChannelState.WAIT_RATCHET_SYNC
    }

    private fun processFirstSessionMessage(msg: LinkReceivedMessage) {
        if ((initiatorSessionParams == null) ||
            (sessionInitKeys == null) ||
            (responderSessionParams == null) ||
            (initiatorHelloRequest == null) ||
            (responderHelloResponse == null) ||
            (encryptedChannel == null)
        ) {
            setError()
            return
        }
        val firstMessage = encryptedChannel!!.decryptMessage(msg.msg, null)
        if (!processHeartbeat(firstMessage)) {
            setError()
            return
        }
        sendHeartbeat()
        initiatorSessionParams = null
        sessionInitKeys = null
        responderSessionParams = null
        initiatorHelloRequest = null
        responderHelloResponse = null
        state = ChannelState.SESSION_ACTIVE
    }

    private fun processSessionMessage(msg: LinkReceivedMessage) {
        if ((encryptedChannel == null)
            || (remoteID == null)
        ) {
            setError()
            return
        }
        val decrypted = encryptedChannel!!.decryptMessage(msg.msg, null)
        if (processHeartbeat(decrypted)) {
            onTick() // check timers
            return
        }
        context.parent.tell(SecureChannelReceivedMessage(linkId, remoteID!!, decrypted), self)
    }

    private fun sendHeartbeat() {
        if ((encryptedChannel == null)
            || (remoteID == null)
        ) {
            setError()
            return
        }
        if (heartbeatSendNonce == null) {
            return
        }
        val heartbeat = Heartbeat.createHeartbeat(heartbeatSendNonce!!, remoteID!!, keyService, fromId)
        heartbeatSendIdentity = VersionedIdentity(keyService.getVersion(fromId).identity, heartbeat.currentVersion)
        heartbeatReceiveNonce = heartbeat.nextExpectedNonce
        heartbeatSendNonce = null
        val heartbeatMessage = encryptedChannel!!.encryptMessage(heartbeat.serialize(), null)
        lastSendTime = Clock.systemUTC().instant()
        //log().info("Send heartbeat $lastSendTime")
        networkActor.tell(LinkSendMessage(linkId, heartbeatMessage), self)
    }

    private fun processHeartbeat(decrypted: ByteArray): Boolean {
        if (heartbeatReceiveNonce != null) {
            val heartbeat = Heartbeat.tryDeserialize(decrypted)
            if (heartbeat != null) { // Possible heartbeat
                val localIdentity = heartbeatSendIdentity!!
                heartbeatSendIdentity = null
                try {
                    remoteID = heartbeat.verify(heartbeatReceiveNonce!!, localIdentity, remoteID!!)
                    val signedEntry = SignedEntry(
                            RouteEntry(heartbeatReceiveNonce!!, remoteID!!),
                        heartbeat.versionedRouteSignature
                    )
                    //val receiveDelay = Duration.between(lastReceiveTime, Clock.systemUTC().instant()).toMillis()
                    //println("heartbeat delay $receiveDelay")
                    updateTimeout()
                    //log().info("Receive heartbeat $lastReceiveTime")
                    heartbeatSendNonce = heartbeat.nextExpectedNonce
                    heartbeatReceiveNonce = null
                    context.parent.tell(SecureChannelRouteUpdate(linkId, localIdentity, signedEntry), self)
                    return true
                } catch (ex: Exception) {
                    // Pass along as message
                    log().error("Heartbeat verify failed")
                }
            }
        }
        return false
    }

    private fun updateTimeout() {
        lastReceiveTime = Clock.systemUTC().instant()
    }

    private fun onSecureChannelSendMessage(msg: SecureChannelSendMessage) {
        if ((encryptedChannel == null)
            || (remoteID == null)
            || (linkId != msg.linkId)
        ) {
            setError()
            return
        }
        val encryptedMsg = encryptedChannel!!.encryptMessage(msg.msg, null)
        networkActor.tell(LinkSendMessage(linkId, encryptedMsg), self)
    }

}