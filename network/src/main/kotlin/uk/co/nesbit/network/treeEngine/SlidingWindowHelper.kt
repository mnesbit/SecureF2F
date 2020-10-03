package uk.co.nesbit.network.treeEngine

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.co.nesbit.network.util.SequenceNumber
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

class DataPacket(
    val sessionId: Long,
    val seqNo: Int,
    val ackSeqNo: Int,
    val selectiveAck: Int,
    val receiveWindowSize: Int,
    val payload: ByteArray
) {
    val isAck: Boolean = payload.isEmpty()
}

class SlidingWindowHelper(val sessionId: Long) {
    companion object {
        const val MAX_SEND_BUFFER = 10
        const val MAX_RECEIVE_BUFFER = 100
        const val START_WINDOW = 8
        const val MAX_WINDOW = 128
        const val START_RTT = 2000L
    }

    private class BufferedPacket(
        val seqNo: Int,
        val payload: ByteArray,
        var lastSent: Instant,
        var retransmitCount: Int = 0
    )

    private val log: Logger = LoggerFactory.getLogger(SlidingWindowHelper::class.java)
    private val unsent = LinkedList<ByteArray>()
    private val sendBuffer = LinkedList<BufferedPacket>()
    private val receiveBuffer = LinkedList<DataPacket>()
    private var rttScaled: Long = START_RTT shl 3
    private var rttVarScaled: Long = 0L
    private var sendSeqNo: Int = 0
    private var sendAckSeqNo: Int = 0
    private var dupAckCount: Int = 0
    private var receiveAckSeqNo: Int = 0
    private var sendWindowsSize: Int = START_WINDOW
    private var receiveWindowSize: Int = START_WINDOW
    private var needAck: Boolean = true
    private var established: Boolean = false

    private fun rttTimeout(): Long {
        return ((rttScaled shr 2) + rttVarScaled) shr 1
    }

    private fun updateRtt(sentTime: Instant, ackTime: Instant) {
        val replyTime = ChronoUnit.MILLIS.between(sentTime, ackTime)
        // Van Jacobson Algorithm for RTT
        if (rttVarScaled == 0L) {
            rttScaled = replyTime shl 3
            rttVarScaled = replyTime shl 1
        } else {
            var replyTimeError = replyTime - (rttScaled shr 3)
            rttScaled += replyTimeError
            if (replyTimeError < 0) {
                replyTimeError = -replyTimeError
            }
            replyTimeError -= (rttVarScaled shr 2)
            rttVarScaled += replyTimeError
        }
    }

    private fun calculateSelectiveAck(): Int {
        var selectiveAck = 0xFFFF
        for (packet in receiveBuffer) {
            val dist = SequenceNumber.distance16(receiveAckSeqNo, packet.seqNo)
            if (dist > 0 && dist < 16) {
                val mask = (1 shl (dist - 1)) xor 0xFFFF
                selectiveAck = selectiveAck and mask
            }
        }
        return selectiveAck
    }

    fun getNearestDeadline(now: Instant): Long {
        val nearest = sendBuffer.minByOrNull { it.lastSent }
        if (nearest != null) {
            return ChronoUnit.MILLIS.between(nearest.lastSent.plusMillis(rttTimeout()), now).coerceAtLeast(0L)
        }
        return rttTimeout()
    }

    fun getMaxRetransmits(): Int {
        if (sendBuffer.isEmpty()) {
            return 0
        }
        return sendBuffer.maxOf { it.retransmitCount }
    }

    fun isEstablished(): Boolean = established

    fun sendPacket(payload: ByteArray): Boolean {
        require(payload.size > 0) {
            "Data array cannot be empty"
        }
        if (unsent.size >= MAX_SEND_BUFFER) {
            return false
        }
        unsent.offer(payload)
        return true
    }

    fun pollReceivedPackets(): List<ByteArray> {
        val received = mutableListOf<ByteArray>()
        while (receiveBuffer.isNotEmpty()) {
            val head = receiveBuffer.peek()
            if (SequenceNumber.compare16(head.seqNo, receiveAckSeqNo) < 0) {
                received += head.payload
                receiveBuffer.poll()
                needAck = true // need to signal changed window
            } else {
                break
            }
        }
        return received
    }

    fun pollForTransmit(now: Instant): List<DataPacket> {
        val sendList = mutableListOf<DataPacket>()
        val timeout = rttTimeout()
        val availableReceiveWindowSize = MAX_RECEIVE_BUFFER - receiveBuffer.size
        var fastResend = false
        if (dupAckCount >= 3) {
            dupAckCount = 0
            fastResend = true
        }
        val selectiveAck = calculateSelectiveAck()
        var resend = false
        for (packet in sendBuffer) {
            val age = ChronoUnit.MILLIS.between(packet.lastSent, now)
            if (age >= timeout || fastResend) {
                ++packet.retransmitCount
                packet.lastSent = now
                sendList += DataPacket(
                    sessionId,
                    packet.seqNo,
                    receiveAckSeqNo,
                    selectiveAck,
                    availableReceiveWindowSize,
                    packet.payload
                )
                resend = true
            }
        }
        if (resend) {
            sendWindowsSize = (sendWindowsSize / 2).coerceAtLeast(START_WINDOW)
        }
        while (unsent.isNotEmpty()
            && sendBuffer.size < sendWindowsSize
            && sendBuffer.size < receiveWindowSize
        ) {
            val seqNo = sendSeqNo
            sendSeqNo = SequenceNumber.increment16(sendSeqNo)
            val packet = BufferedPacket(seqNo, unsent.poll(), now)
            sendBuffer.offer(packet)
            sendList += DataPacket(
                sessionId,
                packet.seqNo,
                receiveAckSeqNo,
                selectiveAck,
                availableReceiveWindowSize,
                packet.payload
            )
        }
        if (sendList.isEmpty() && needAck) {
            if (receiveBuffer.none { SequenceNumber.compare16(it.seqNo, receiveAckSeqNo) >= 0 }
                && established) {
                needAck = false
            }
            sendList += DataPacket(
                sessionId,
                sendSeqNo,
                receiveAckSeqNo,
                selectiveAck,
                availableReceiveWindowSize,
                ByteArray(0)
            )
        }
        for (item in sendList) {
            log.info("send seq ${item.seqNo} ack ${item.ackSeqNo} sack ${item.selectiveAck.toString(2)} window ${item.receiveWindowSize}")
        }
        return sendList
    }

    fun processMessage(message: DataPacket, now: Instant) {
        if (message.sessionId != sessionId) {
            return
        }
        log.info("receive seq ${message.seqNo} ack ${message.ackSeqNo}  sack ${message.selectiveAck.toString(2)} window ${message.receiveWindowSize}")
        receiveWindowSize = message.receiveWindowSize
        established = true
        val ackComp = SequenceNumber.distance16(sendAckSeqNo, message.ackSeqNo)
        if (message.isAck && ackComp == 0) {
            ++dupAckCount
        } else if (SequenceNumber.inRange16(ackComp) && ackComp > 0) {
            dupAckCount = 0
            sendAckSeqNo = message.ackSeqNo
            val packetItr = sendBuffer.iterator()
            while (packetItr.hasNext()) {
                val packet = packetItr.next()
                val dist = SequenceNumber.distance16(message.ackSeqNo, packet.seqNo)
                var drop = false
                if (dist < 0) {
                    drop = true
                } else if (dist > 0 && dist < 16) {
                    if (message.selectiveAck and (1 shl (dist - 1)) == 0) {
                        drop = true
                    }
                }
                if (drop) {
                    packetItr.remove()
                    if (packet.retransmitCount == 0) {
                        updateRtt(packet.lastSent, now)
                        sendWindowsSize = (sendWindowsSize + 1).coerceAtMost(MAX_WINDOW)
                    }
                }
            }
        }
        if (message.isAck) {
            return
        }
        needAck = true
        if (receiveBuffer.size >= MAX_RECEIVE_BUFFER) {
            return
        }
        val distance = SequenceNumber.distance16(receiveAckSeqNo, message.seqNo)
        if (!SequenceNumber.inRange16(distance)) {
            return
        }
        var index = 0
        var added = false
        for (item in receiveBuffer) {
            val comp = SequenceNumber.compare16(item.seqNo, message.seqNo)
            if (comp == 0) {
                return
            } else if (comp > 0) {
                receiveBuffer.add(index, message)
                added = true
                break
            }
            ++index
        }
        if (!added) {
            receiveBuffer.add(message)
        }
        for (item in receiveBuffer) {
            if (item.seqNo == receiveAckSeqNo) {
                receiveAckSeqNo = SequenceNumber.increment16(receiveAckSeqNo)
            }
        }
    }
}