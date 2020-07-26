package uk.co.nesbit.network.tcpnet

import akka.actor.ActorRef
import akka.actor.Props
import akka.actor.Terminated
import akka.io.Tcp
import akka.io.TcpMessage
import akka.util.ByteString
import uk.co.nesbit.network.api.LinkId
import uk.co.nesbit.network.api.LinkStatus
import uk.co.nesbit.network.api.PublicAddress
import uk.co.nesbit.network.api.net.CloseRequest
import uk.co.nesbit.network.api.net.LinkReceivedMessage
import uk.co.nesbit.network.api.net.LinkSendMessage
import uk.co.nesbit.network.util.UntypedBaseActorWithLoggingAndTimers
import uk.co.nesbit.network.util.createProps
import java.net.InetSocketAddress
import java.nio.ByteOrder
import java.time.Clock
import java.util.*

class TcpLinkActor(private val linkId: LinkId, private val connectTo: PublicAddress?) :
        UntypedBaseActorWithLoggingAndTimers() {
    companion object {
        @JvmStatic
        fun getProps(linkId: LinkId, connectTo: PublicAddress?): Props {
            @Suppress("JAVA_CLASS_ON_COMPANION")
            return createProps(javaClass.enclosingClass, linkId, connectTo)
        }

        const val LEAD_IN_SIZE = 10
        const val MAX_BUFFER_SIZE = 100
    }

    private class Ack(val seqNo: Long) : Tcp.Event

    private var tcpActor: ActorRef? = null
    private var connected: Boolean = false
    private var writesBlocked: Boolean = false
    private var ackedSeqNo: Long = 0L
    private var nackedSeqNo: Long = 0L
    private var leadIn: Int = 0
    private val bufferedWrites: Queue<ByteString> = LinkedList<ByteString>()
    private var bufferedReads: ByteString = ByteString.emptyByteString()

    override fun preStart() {
        super.preStart()
        //log().info("Starting TcpLinkActor")
        if (connectTo != null) {
            val targetAddress = InetSocketAddress.createUnresolved(connectTo.host, connectTo.port)
            val tcpManager = Tcp.get(context.system).manager()
            tcpManager.tell(TcpMessage.connect(targetAddress), self)
        }
    }

    override fun postStop() {
        super.postStop()
        //log().info("Stopped TcpLinkActor")
    }

    override fun postRestart(reason: Throwable?) {
        super.postRestart(reason)
        //log().info("Restart TcpLinkActor")
    }

    override fun onReceive(message: Any) {
        when (message) {
            is Tcp.CommandFailed -> onFailedCommand(message)
            is Tcp.Connected -> onConnected(message)
            is Tcp.ConnectionClosed -> onClosed(message)
            is Tcp.Received -> onReceivedBytes(message)
            is Tcp.Event -> onEvent(message)
            is LinkSendMessage -> onLinkSendMessage(message)
            is CloseRequest -> onCloseRequest()
            is Terminated -> onTerminated(message)
            else -> log().warning("Unrecognised message $message")
        }
    }

    private fun onLinkSendMessage(message: LinkSendMessage) {
        //log().info("LinkSendMessage ${message.msg.size} bytes ${message.msg.printHexBinary()}")
        if (bufferedWrites.size >= MAX_BUFFER_SIZE) {
            log().warning("dropping packet due to full buffer")
            return
        }
        val packetBuilder = ByteString.newBuilder()
        packetBuilder.sizeHint(message.msg.size + 4)
        packetBuilder.putInt(message.msg.size, ByteOrder.BIG_ENDIAN)
        packetBuilder.putBytes(message.msg)
        val packet = packetBuilder.result()
        val seqNo = ackedSeqNo + bufferedWrites.size
        bufferedWrites.add(packet)
        if (!writesBlocked) {
            tcpActor!!.tell(TcpMessage.write(packet, Ack(seqNo)), self)
        }
    }

    private fun onConnected(message: Tcp.Connected) {
        log().info(
                "Tcp Connected $linkId ${message.localAddress()}" +
                        (if (connectTo != null) "->" else "<-") +
                        "${message.remoteAddress()}"
        )
        tcpActor = sender
        context.watch(tcpActor)
        sender.tell(TcpMessage.register(self, false, true), self)
        connected = true
        context.parent.tell(
                TcpNetworkActor.ConnectResult(
                        linkId,
                        if (connectTo != null) LinkStatus.LINK_UP_ACTIVE else LinkStatus.LINK_UP_PASSIVE
                ), self
        )
    }

    private fun onCloseRequest() {
        //log().info("CloseRequest")
        tcpActor?.tell(TcpMessage.close(), self)
    }

    @Suppress("UNUSED_PARAMETER")
    private fun onClosed(message: Tcp.ConnectionClosed) {
        connected = false
        //log().info("Tcp Connection ${linkId} Closed ${message}")
        context.parent.tell(TcpNetworkActor.LinkLost(linkId), self)
        context.stop(self)
    }

    private fun onTerminated(message: Terminated) {
        if (message.actor == tcpActor) {
            //log().warning("Tcp actor exited stopping")
            context.parent.tell(TcpNetworkActor.LinkLost(linkId), self)
            context.stop(self)
        }
    }

    private fun onEvent(message: Tcp.Event) {
        //log().info("Received event $message")
        if (message is Ack) {
            processAck(message)
        } else if (message is Tcp.WritingResumed) {
            //log().info("writing resumed $linkId ${bufferedWrites.size}")
            //log().info("send single $ackedSeqNo")
            tcpActor!!.tell(TcpMessage.write(bufferedWrites.peek(), Ack(ackedSeqNo)), self)
        }
    }

    private fun processAck(message: Ack) {
        //log().info("Received Ack of ${message.seqNo}")
        if (ackedSeqNo == message.seqNo) {
            bufferedWrites.remove()
            ++ackedSeqNo
            //log().info("${linkId} ackedSeqNo $ackedSeqNo buffered ${bufferedWrites.size} current seq ${ackedSeqNo + bufferedWrites.size}")
        } else {
            log().error("bad ack ${message.seqNo} expected $ackedSeqNo")
        }
        if (writesBlocked) {
            if (message.seqNo >= nackedSeqNo && bufferedWrites.isNotEmpty()) {
                if (leadIn > 0) {
                    //log().info("send single $ackedSeqNo")
                    tcpActor!!.tell(TcpMessage.write(bufferedWrites.peek(), Ack(ackedSeqNo)), self)
                    --leadIn
                } else {
                    //log().info("send all")
                    for ((offset, data) in bufferedWrites.withIndex()) {
                        tcpActor!!.tell(TcpMessage.write(data, Ack(ackedSeqNo + offset)), self)
                    }
                    writesBlocked = false
                }
            }
        }
    }

    private fun onReceivedBytes(message: Tcp.Received) {
        //log().info("Received packet $message")
        bufferedReads = bufferedReads.concat(message.data())
        //log().info("receive length ${bufferedReads.length()}")
        while (true) {
            if (bufferedReads.length() < 4) {
                break
            }
            val header = bufferedReads.slice(0, 4)
            val length = header.asByteBuffer().int
            if (bufferedReads.length() < 4 + length) {
                break
            }
            //log().info("link received message $length")
            val buff1 = bufferedReads.drop(4)
            val packet = buff1.take(length).toArray()
            //log().info("packet ${packet.size} bytes ${packet.printHexBinary()}")
            context.parent.tell(LinkReceivedMessage(linkId, Clock.systemUTC().instant(), packet), self)
            bufferedReads = buff1.drop(length)
            //log().info("new receive length ${bufferedReads.length()}")
        }
    }

    private fun onFailedCommand(message: Tcp.CommandFailed) {
        when (message.cmd()) {
            is Tcp.Connect -> {
                log().error("Unable to connect to $connectTo")
                connected = false
                context.parent.tell(TcpNetworkActor.ConnectResult(linkId, LinkStatus.LINK_DOWN), self)
                context.stop(self)
            }
            is Tcp.Write -> {
                handleWriteNack(message.cmd() as Tcp.Write)
            }
            else -> log().warning("${message.cmd()} failed with ${message.causedByString()}")
        }

    }

    private fun handleWriteNack(cmd: Tcp.Write) {
        if (!writesBlocked) {
            //log().info("${linkId} got write nack ${bufferedWrites.size}")
            writesBlocked = true
            nackedSeqNo = (cmd.ack() as Ack).seqNo
            leadIn = LEAD_IN_SIZE
            tcpActor!!.tell(TcpMessage.resumeWriting(), self)
        }
    }

}
