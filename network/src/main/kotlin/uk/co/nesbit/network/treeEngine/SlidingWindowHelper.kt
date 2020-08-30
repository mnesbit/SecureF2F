package uk.co.nesbit.network.treeEngine

import uk.co.nesbit.network.util.SequenceNumber
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

class DataPacket(
    val sessionId: Long,
    val seqNo: Int,
    val ackSeqNo: Int,
    val receiveWindowSize: Int,
    val payload: ByteArray
)

class SlidingWindowHelper(val sessionId: Long) {
    companion object {
        const val MAX_SEND_BUFFER = 10
        const val MAX_RECEIVE_BUFFER = 100
        const val START_WINDOW = 8
        const val MAX_WINDOW = 128
        const val START_RTT = 10000L
    }

    private class BufferedPacket(
        val seqNo: Int,
        val payload: ByteArray,
        var lastSent: Instant,
        var restransmitted: Boolean = false
    )

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

    fun sendPacket(payload: ByteArray): Boolean {
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
        var resend = false
        for (packet in sendBuffer) {
            val age = ChronoUnit.MILLIS.between(packet.lastSent, now)
            if (age >= timeout || fastResend) {
                packet.restransmitted = true
                packet.lastSent = now
                sendList += DataPacket(
                    sessionId,
                    packet.seqNo,
                    receiveAckSeqNo,
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
            val packet = BufferedPacket(sendSeqNo++, unsent.poll(), now)
            sendBuffer.offer(packet)
            sendList += DataPacket(
                sessionId,
                packet.seqNo,
                receiveAckSeqNo,
                availableReceiveWindowSize,
                packet.payload
            )
        }
        if (sendList.isEmpty()) {
            sendList += DataPacket(
                sessionId,
                sendSeqNo,
                receiveAckSeqNo,
                availableReceiveWindowSize,
                ByteArray(0)
            )
        }
        return sendList
    }

    fun processMessage(message: DataPacket, now: Instant) {
        if (message.sessionId != sessionId) {
            return
        }
        receiveWindowSize = message.receiveWindowSize
        val ackComp = SequenceNumber.distance16(sendAckSeqNo, message.ackSeqNo)
        if (message.payload.isEmpty() && ackComp == 0) {
            ++dupAckCount
        } else if (SequenceNumber.inRange16(ackComp) && ackComp > 0) {
            dupAckCount = 0
            sendAckSeqNo = message.ackSeqNo
            while (sendBuffer.isNotEmpty()) {
                val head = sendBuffer.peek()
                if (SequenceNumber.compare16(head.seqNo, sendAckSeqNo) < 0) {
                    sendBuffer.poll()
                    if (!head.restransmitted) {
                        updateRtt(head.lastSent, now)
                        sendWindowsSize = (sendWindowsSize + 1).coerceAtMost(MAX_WINDOW)
                    }
                } else {
                    break
                }
            }
        }
        if (message.payload.isEmpty()) { // ack packet
            return
        }
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
                ++receiveAckSeqNo
            }
        }
    }
}