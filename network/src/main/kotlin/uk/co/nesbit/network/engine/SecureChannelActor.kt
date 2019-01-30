package uk.co.nesbit.network.engine

import akka.actor.AbstractLoggingActor
import akka.actor.ActorRef
import akka.actor.Cancellable
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
import java.security.KeyPair

class NeighbourReceivedMessage(val linkId: LinkId, val sourceId: VersionedIdentity, val msg: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NeighbourReceivedMessage

        if (linkId != other.linkId) return false
        if (sourceId != other.sourceId) return false
        if (!msg.contentEquals(other.msg)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = linkId.hashCode()
        result = 31 * result + sourceId.hashCode()
        result = 31 * result + msg.contentHashCode()
        return result
    }
}

data class SecureChannelClose(val linkId: LinkId)

class SecureChannelActor(
    val linkId: LinkId,
    private val fromId: SecureHash,
    private val initiator: Boolean,
    private val keyService: KeyService,
    private val networkActor: ActorRef
) : AbstractLoggingActor() {
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
            return Props.create(javaClass.enclosingClass, linkId, fromId, initiator, keyService, networkActor)
        }
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

    private var timer: Cancellable? = null
    private var state: ChannelState = ChannelState.INIT
    private var sessionInitKeys: KeyPair? = null
    private var initiatorSessionParams: InitiatorSessionParams? = null
    private var responderSessionParams: ResponderSessionParams? = null
    private var initiatorHelloRequest: InitiatorHelloRequest? = null
    private var responderHelloResponse: ResponderHelloResponse? = null
    private var encryptedChannel: RatchetState? = null
    private val earlyMessages = mutableListOf<ByteArray>()
    private var heartbeatSendNonce: ByteArray? = null
    private var heartbeatReceiveNonce: ByteArray? = null
    private var remoteID: VersionedIdentity? = null
    private var routeEntry: Pair<Int, SignedEntry>? = null

    override fun preStart() {
        super.preStart()
        log().info("Starting SecureChannelActor $linkId")
        onInit()
    }

    override fun postStop() {
        super.postStop()
        log().info("Stopped SecureChannelActor $linkId")
        timer?.cancel()
        timer = null
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        log().info("Restart SecureChannelActor $linkId")
    }

    override fun createReceive(): Receive =
        ReceiveBuilder()
            .match(LinkReceivedMessage::class.java, ::onMessage)
            .match(Tick::class.java) { onTick() }
            .build()

    private fun onTick() {
        log().info("onTick")
    }


    private fun onMessage(message: LinkReceivedMessage) {
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
        val responderSession = ResponderSessionParams.deserialize(msg.msg)
        responderSession.verify(initiatorSessionParams!!)
        responderSessionParams = responderSession
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
        if (earlyMessages.isNotEmpty()) {
            for (message in earlyMessages) {
                context.parent.tell(NeighbourReceivedMessage(linkId, remoteID!!, message), self)
            }
            earlyMessages.clear()
        }
    }

    private fun processSessionMessage(msg: LinkReceivedMessage) {
        if ((encryptedChannel == null)
            || (remoteID == null)
        ) {
            setError()
            return
        }
        val decrypted = encryptedChannel!!.decryptMessage(msg.msg, null)
        if (processHeartbeat(decrypted)) return
        context.parent.tell(NeighbourReceivedMessage(linkId, remoteID!!, decrypted), self)
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
        heartbeatReceiveNonce = heartbeat.nextExpectedNonce
        heartbeatSendNonce = null
        val heartbeatMessage = encryptedChannel!!.encryptMessage(heartbeat.serialize(), null)
        networkActor.tell(LinkSendMessage(linkId, heartbeatMessage), self)
    }

    private fun processHeartbeat(decrypted: ByteArray): Boolean {
        if (heartbeatReceiveNonce != null) {
            val heartbeat = Heartbeat.tryDeserialize(decrypted)
            if (heartbeat != null) { // Possible heartbeat
                val localIdentity = keyService.getVersion(fromId)
                try {
                    remoteID = heartbeat.verify(heartbeatReceiveNonce!!, localIdentity, remoteID!!)
                    routeEntry = Pair(
                        localIdentity.currentVersion.version,
                        SignedEntry(
                            RouteEntry(heartbeatReceiveNonce!!, remoteID!!),
                            heartbeat.versionedRouteSignature
                        )
                    )
                    heartbeatSendNonce = heartbeat.nextExpectedNonce
                    heartbeatReceiveNonce = null
                    return true
                } catch (ex: Exception) {
                    // Pass along as message
                    log().error("Heartbeat verify failed")
                }
            }
        }
        return false
    }

}