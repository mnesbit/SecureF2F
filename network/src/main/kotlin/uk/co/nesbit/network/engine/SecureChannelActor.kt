//package uk.co.nesbit.network.engine
//
//import akka.actor.AbstractLoggingActor
//import akka.actor.ActorRef
//import akka.actor.Cancellable
//import akka.actor.Props
//import akka.japi.pf.ReceiveBuilder
//import uk.co.nesbit.network.api.*
//import uk.co.nesbit.network.util.seconds
//
//data class VersionUpdate(val version: Int)
//data class LinkHeartbeat(val linkId: LinkId, val remoteAddress: VersionedAddress)
//
//class SecureChannelActor(
//    val linkId: LinkId,
//    val overlayAddress: Address,
//    val initiator: Boolean,
//    val networkActor: ActorRef
//) : AbstractLoggingActor() {
//    companion object {
//        @JvmStatic
//        fun getProps(linkId: LinkId, overlayAddress: Address, initiator: Boolean, networkActor: ActorRef): Props {
//            @Suppress("JAVA_CLASS_ON_COMPANION")
//            return Props.create(javaClass.enclosingClass, linkId, overlayAddress, initiator, networkActor)
//        }
//    }
//
//    private class Tick
//
//    private var version: Int = 0
//    private var remoteId: VersionedAddress? = null
//    private var timer: Cancellable? = null
//    private var heartbeatDue: Boolean = false
//
//    override fun preStart() {
//        super.preStart()
//        log().info("Starting SecureChannelActor $overlayAddress")
//    }
//
//    override fun postStop() {
//        super.postStop()
//        log().info("Stopped SecureChannelActor $overlayAddress")
//        timer?.cancel()
//        timer = null
//    }
//
//    override fun postRestart(reason: Throwable?) {
//        super.postRestart(reason)
//        log().info("Restart SecureChannelActor $overlayAddress")
//    }
//
//    override fun createReceive(): Receive =
//        ReceiveBuilder()
//            .match(VersionUpdate::class.java, ::onVersionUpdate)
//            .match(LinkReceivedMessage::class.java, ::onMessage)
//            .match(Tick::class.java) { onTick() }
//            .build()
//
//    private fun onVersionUpdate(versionUpdate: VersionUpdate) {
//        log().info("onVersionUpdate")
//        version = versionUpdate.version
//        if (initiator) {
//            networkActor.tell(
//                SendMessage(linkId, "HandshakeI1|$overlayAddress|$version".toByteArray(Charsets.UTF_8)),
//                self
//            )
//        }
//    }
//
//    private fun onTick() {
//        log().info("onTick")
//        if (heartbeatDue) {
//            heartbeatDue = false
//            networkActor.tell(
//                SendMessage(linkId, "Heartbeat|$overlayAddress|$version".toByteArray(Charsets.UTF_8)),
//                self
//            )
//        }
//    }
//
//    private fun onMessage(message: LinkReceivedMessage) {
//        val msgString = message.msg.toString(Charsets.UTF_8)
//        log().info("Processing $msgString")
//        val segments = msgString.split("|")
//        val remoteAddress = OverlayAddress(segments[1].substringAfter("[").substringBefore("]").toInt())
//        val versionNo = segments[2].toInt()
//        remoteId = VersionedAddress(remoteAddress, versionNo)
//        when (segments[0]) {
//            "HandshakeI1" -> {
//                networkActor.tell(
//                    SendMessage(
//                        linkId,
//                        "HandshakeR1|$overlayAddress|$version".toByteArray(Charsets.UTF_8)
//                    ), self
//                )
//            }
//            "HandshakeR1" -> {
//                networkActor.tell(
//                    SendMessage(linkId, "Heartbeat|$overlayAddress|$version".toByteArray(Charsets.UTF_8)),
//                    self
//                )
//                timer = context.system.scheduler().schedule(
//                    0.seconds(),
//                    1.seconds(), self, Tick(),
//                    context.system.dispatcher(), null
//                )
//            }
//            "Heartbeat" -> {
//                heartbeatDue = true
//                if (timer == null) {
//                    timer = context.system.scheduler().schedule(
//                        1.seconds(),
//                        1.seconds(), self, Tick(),
//                        context.system.dispatcher(), null
//                    )
//                }
//            }
//        }
//        context.parent.tell(LinkHeartbeat(linkId, remoteId!!), self)
//    }
//
//}