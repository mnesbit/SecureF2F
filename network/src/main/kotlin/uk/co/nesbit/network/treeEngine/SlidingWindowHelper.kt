package uk.co.nesbit.network.treeEngine

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import uk.co.nesbit.network.treeEngine.DataPacket.Companion.CLOSE_MARKER
import uk.co.nesbit.network.treeEngine.DataPacket.Companion.OPEN_ACK_MARKER
import uk.co.nesbit.network.treeEngine.DataPacket.Companion.OPEN_MARKER
import uk.co.nesbit.network.treeEngine.DataPacket.Companion.RESET_MARKER
import uk.co.nesbit.network.util.SequenceNumber
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

data class DataPacket(
    val sessionId: Long,
    val seqNo: Int,
    val ackSeqNo: Int,
    val selectiveAck: Int,
    val receiveWindowSize: Int,
    val payload: ByteArray
) {
    companion object {
        const val OPEN_MARKER = -0xA110
        const val OPEN_ACK_MARKER = -0xE110
        const val CLOSE_MARKER = -0xDEAD
        const val RESET_MARKER = -0xAAAA

        val AckBody = ByteArray(0)
    }

    enum class DataPacketType {
        NORMAL,
        ACK,
        OPEN,
        OPEN_ACK,
        CLOSE,
        RESET
    }

    val isAck: Boolean = payload.isEmpty()

    val packetType: DataPacketType
        get() {
            if (receiveWindowSize < 0 || selectiveAck < 0) {
                if (!isAck) {
                    return DataPacketType.RESET
                }
                if (seqNo == 0
                    && (receiveWindowSize == OPEN_MARKER)
                    && (selectiveAck == OPEN_MARKER)
                ) {
                    return DataPacketType.OPEN
                }
                if (seqNo == 0
                    && ackSeqNo == 0
                    && (receiveWindowSize == OPEN_ACK_MARKER)
                    && (selectiveAck == OPEN_ACK_MARKER)
                ) {
                    return DataPacketType.OPEN_ACK
                }
                if ((receiveWindowSize == CLOSE_MARKER)
                    && (selectiveAck == CLOSE_MARKER)
                ) {
                    return DataPacketType.CLOSE
                }
                return DataPacketType.RESET
            }

            if (!isAck) {
                return DataPacketType.NORMAL
            }
            return DataPacketType.ACK
        }
}

class SlidingWindowHelper(val sessionId: Long) {
    companion object {
        const val MAX_SEND_BUFFER = 10
        const val MAX_RECEIVE_BUFFER = 100
        const val START_WINDOW = 8
        const val MAX_WINDOW = 128
        const val OPEN_TIMEOUT = 15000L
        const val CLOSE_TIMEOUT = 15000L
    }

    private class BufferedPacket(
        val seqNo: Int,
        val isClose: Boolean,
        val payload: ByteArray,
        var lastSent: Instant,
        var retransmitCount: Int = 0
    )

    private enum class ConnectionState {
        Created,
        InitialOpenSent,
        InitialOpenReceived,
        Established,
        Closing,
        Closed
    }

    private val log: Logger = LoggerFactory.getLogger(SlidingWindowHelper::class.java)
    private val unsent = LinkedList<ByteArray>()
    private val sendBuffer = LinkedList<BufferedPacket>()
    private val receiveBuffer = LinkedList<DataPacket>()
    private var rtt = TimeoutEstimator(TimeoutEstimator.START_RTT)
    private var sendSeqNo: Int = 0
    private var sendAckSeqNo: Int = 0
    private var dupAckCount: Int = 0
    private var receiveAckSeqNo: Int = 0
    private var sendWindowsSize: Int = START_WINDOW
    private var receiveWindowSize: Int = START_WINDOW
    private var needAck: Boolean = true
    private var connectionState: ConnectionState = ConnectionState.Created
    private var openStarted: Instant = Instant.MAX
    private var closingStarted: Instant = Instant.MAX
    private var closeAcked: Boolean = false
    private var closeReceived: Boolean = false

    private fun rttTimeout(): Long = rtt.rttTimeout()

    private fun updateRtt(sentTime: Instant, ackTime: Instant) = rtt.updateRtt(sentTime, ackTime)

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

    private fun updateState(packet: DataPacket, now: Instant) {
        val flags = packet.packetType
        when (connectionState) {
            ConnectionState.Created -> {
                when (flags) {
                    DataPacket.DataPacketType.OPEN -> {
                        needAck = true
                        connectionState = ConnectionState.InitialOpenReceived
                    }
                    DataPacket.DataPacketType.OPEN_ACK -> {
                        needAck = true
                        connectionState = ConnectionState.InitialOpenReceived
                    }
                    DataPacket.DataPacketType.CLOSE -> {
                        closingStarted = now
                        connectionState = ConnectionState.Closing
                    }
                    DataPacket.DataPacketType.RESET -> {
                        closingStarted = now.minusMillis(3L * rttTimeout())
                        shutdownSession()
                    }
                    else -> {
                        connectionState = ConnectionState.Created
                    }
                }
            }
            ConnectionState.InitialOpenSent -> {
                when (flags) {
                    DataPacket.DataPacketType.OPEN -> {
                        connectionState = ConnectionState.InitialOpenReceived
                    }
                    DataPacket.DataPacketType.OPEN_ACK -> {
                        needAck = true
                        connectionState = ConnectionState.Established
                    }
                    DataPacket.DataPacketType.CLOSE -> {
                        closingStarted = now
                        connectionState = ConnectionState.Closing
                    }
                    DataPacket.DataPacketType.RESET -> {
                        closingStarted = now.minusMillis(3L * rttTimeout())
                        shutdownSession()
                    }
                    else -> {
                        connectionState = ConnectionState.InitialOpenSent
                    }
                }
            }
            ConnectionState.InitialOpenReceived -> {
                when (flags) {
                    DataPacket.DataPacketType.OPEN_ACK -> {
                        needAck = true
                        connectionState = ConnectionState.Established
                    }
                    DataPacket.DataPacketType.ACK -> {
                        needAck = true
                        connectionState = ConnectionState.Established
                    }
                    DataPacket.DataPacketType.NORMAL -> {
                        needAck = true
                        connectionState = ConnectionState.Established
                    }
                    DataPacket.DataPacketType.CLOSE -> {
                        closingStarted = now
                        connectionState = ConnectionState.Closing
                    }
                    DataPacket.DataPacketType.RESET -> {
                        closingStarted = now.minusMillis(3L * rttTimeout())
                        shutdownSession()
                    }
                    else -> {
                        connectionState = ConnectionState.InitialOpenReceived
                    }
                }
            }
            ConnectionState.Established -> {
                when (flags) {
                    DataPacket.DataPacketType.OPEN -> {
                        needAck = true
                        connectionState = ConnectionState.Established
                    }
                    DataPacket.DataPacketType.OPEN_ACK -> {
                        needAck = true
                        connectionState = ConnectionState.Established
                    }
                    DataPacket.DataPacketType.CLOSE -> {
                        closingStarted = now
                        connectionState = ConnectionState.Closing
                    }
                    DataPacket.DataPacketType.RESET -> {
                        closingStarted = now.minusMillis(3L * rttTimeout())
                        shutdownSession()
                    }
                    else -> {
                        connectionState = ConnectionState.Established
                    }
                }
            }
            ConnectionState.Closing -> {
                when (flags) {
                    DataPacket.DataPacketType.RESET -> {
                        closingStarted = now.minusMillis(3L * rttTimeout())
                        shutdownSession()
                    }
                    else -> {
                        connectionState = ConnectionState.Closing
                    }
                }
            }
            ConnectionState.Closed -> {
                // Terminal state do nothing
                shutdownSession()
            }
        }
    }

    private fun shutdownSession() {
        connectionState = ConnectionState.Closed
        unsent.clear()
        sendBuffer.clear()
        receiveBuffer.clear()
    }

    fun getNearestDeadline(now: Instant): Long {
        val nearest = sendBuffer.minByOrNull { it.lastSent }
        val rttTimeout = rttTimeout()
        if (nearest != null) {
            return ChronoUnit.MILLIS.between(now, nearest.lastSent.plusMillis(rttTimeout())).coerceAtLeast(1L)
        }
        return rttTimeout
    }

    fun getMaxRetransmits(): Int {
        if (sendBuffer.isEmpty()) {
            return 0
        }
        return sendBuffer.maxOf { it.retransmitCount }
    }

    fun isEstablished(): Boolean = (connectionState == ConnectionState.Established)

    fun isTerminated(): Boolean = (connectionState == ConnectionState.Closed)

    fun sendPacket(payload: ByteArray): Boolean {
        require(payload.size > 0) {
            "Data array cannot be empty"
        }
        if (connectionState == ConnectionState.Closing
            || connectionState == ConnectionState.Closed
        ) {
            return false
        }
        if (unsent.size >= MAX_SEND_BUFFER) {
            return false
        }
        unsent.offer(payload)
        return true
    }

    fun pollReceivedPackets(): List<ByteArray> {
        if (connectionState != ConnectionState.Established
            && connectionState != ConnectionState.Closing
        ) {
            return emptyList()
        }
        val received = mutableListOf<ByteArray>()
        while (receiveBuffer.isNotEmpty()) {
            val head = receiveBuffer.peek()
            if (SequenceNumber.distance16(receiveAckSeqNo, head.seqNo) < 0) {
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
        return when (connectionState) {
            ConnectionState.Created,
            ConnectionState.InitialOpenSent,
            ConnectionState.InitialOpenReceived -> connectionOpenPollForTransmit(now)
            ConnectionState.Established -> establishedPollForTransmit(now)
            ConnectionState.Closing -> connectionClosingPollForTransmit(now)
            ConnectionState.Closed -> listOf(
                DataPacket(
                    sessionId,
                    sendSeqNo,
                    receiveAckSeqNo,
                    RESET_MARKER,
                    RESET_MARKER,
                    DataPacket.AckBody
                )
            )
        }
    }

    fun closeSession(now: Instant) {
        if (connectionState != ConnectionState.Closing
            && connectionState != ConnectionState.Closed
        ) {
            closingStarted = now
            connectionState = ConnectionState.Closing
        }
    }

    private fun connectionOpenPollForTransmit(now: Instant): List<DataPacket> {
        if (connectionState == ConnectionState.Created) {
            connectionState = ConnectionState.InitialOpenSent
        }
        if (openStarted == Instant.MAX) {
            openStarted = now
        } else if (ChronoUnit.MILLIS.between(openStarted, now) >= OPEN_TIMEOUT) {
            shutdownSession()
            return listOf(
                DataPacket(
                    sessionId,
                    sendSeqNo,
                    receiveAckSeqNo,
                    RESET_MARKER,
                    RESET_MARKER,
                    DataPacket.AckBody
                )
            )
        }
        val packetType = if (connectionState == ConnectionState.InitialOpenReceived) OPEN_ACK_MARKER else OPEN_MARKER
        return listOf(
            DataPacket(
                sessionId,
                0,
                0,
                packetType,
                packetType,
                DataPacket.AckBody
            )
        )
    }

    private fun establishedPollForTransmit(now: Instant): List<DataPacket> {
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
        for (packet in sendBuffer.sortedBy { it.lastSent }) {
            val age = ChronoUnit.MILLIS.between(packet.lastSent, now)
            val backoff = (1L shl packet.retransmitCount)
            if (age >= timeout * backoff || (fastResend && packet.retransmitCount == 0)) {
                ++packet.retransmitCount
                packet.lastSent = now
                sendList += DataPacket(
                    sessionId,
                    packet.seqNo,
                    receiveAckSeqNo,
                    if (!packet.isClose) selectiveAck else CLOSE_MARKER,
                    if (!packet.isClose) availableReceiveWindowSize else CLOSE_MARKER,
                    packet.payload
                )
                log.info("SENDING ${packet.seqNo} $now retries ${packet.retransmitCount}")
                resend = true
                if (sendList.size >= sendWindowsSize) break
            }
        }
        if (resend) {
            sendWindowsSize = (sendWindowsSize / 2).coerceAtLeast(START_WINDOW)
        }
        while (unsent.isNotEmpty()
            && sendList.size < sendWindowsSize
            && sendBuffer.size < sendWindowsSize
            && sendBuffer.size < receiveWindowSize
        ) {
            val seqNo = sendSeqNo
            sendSeqNo = SequenceNumber.increment16(sendSeqNo)
            val packet = BufferedPacket(seqNo, false, unsent.poll(), now)
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
            if (receiveBuffer.none { SequenceNumber.distance16(receiveAckSeqNo, it.seqNo) >= 0 }
                && isEstablished()) {
                needAck = false
            }
            sendList += DataPacket(
                sessionId,
                sendSeqNo,
                receiveAckSeqNo,
                selectiveAck,
                availableReceiveWindowSize,
                DataPacket.AckBody
            )
        }
        for (item in sendList) {
            log.info("send ${item.packetType} seq ${item.seqNo} ack ${item.ackSeqNo} sack ${item.selectiveAck.toString(2)} window ${item.receiveWindowSize}")
        }
        return sendList
    }

    private fun connectionClosingPollForTransmit(now: Instant): List<DataPacket> {
        if (closeReceived
            && closeAcked
            && ChronoUnit.MILLIS.between(closingStarted, now) > 3L * rttTimeout()
        ) {
            shutdownSession()
            return emptyList()
        } else if (ChronoUnit.MILLIS.between(closingStarted, now) > CLOSE_TIMEOUT) {
            shutdownSession()
            return listOf(
                DataPacket(
                    sessionId,
                    sendSeqNo,
                    receiveAckSeqNo,
                    RESET_MARKER,
                    RESET_MARKER,
                    DataPacket.AckBody
                )
            )
        }
        if (unsent.isEmpty() && !sendBuffer.any { it.isClose }) {
            val seqNo = sendSeqNo
            sendSeqNo = SequenceNumber.increment16(sendSeqNo)
            val packet = BufferedPacket(seqNo, true, DataPacket.AckBody, Instant.EPOCH)
            sendBuffer.offer(packet)
        }
        needAck = false
        return establishedPollForTransmit(now)
    }

    private fun updateReceiveAckSeqNo() {
        for (item in receiveBuffer) {
            if (item.seqNo == receiveAckSeqNo) {
                receiveAckSeqNo = SequenceNumber.increment16(receiveAckSeqNo)
                needAck = true
            }
        }
    }

    private fun updateSendAckSeqNo(
        message: DataPacket,
        packetType: DataPacket.DataPacketType,
        now: Instant
    ) {
        dupAckCount = 0
        sendAckSeqNo = message.ackSeqNo
        val packetItr = sendBuffer.iterator()
        while (packetItr.hasNext()) {
            val packet = packetItr.next()
            val dist = SequenceNumber.distance16(message.ackSeqNo, packet.seqNo)
            var drop = false
            if (dist < 0) { // offset 0 ignored as it is always one beyond consolidated seqNo
                drop = true
            } else if (dist > 0 && dist < 16) {
                if ((packetType == DataPacket.DataPacketType.NORMAL
                            || packetType == DataPacket.DataPacketType.ACK)
                    && message.selectiveAck and (1 shl (dist - 1)) == 0
                ) {
                    drop = true
                }
            }
            if (drop) {
                if (!packet.isClose) {
                    packetItr.remove()
                    if (packet.retransmitCount == 0) {
                        updateRtt(packet.lastSent, now)
                        sendWindowsSize = (sendWindowsSize + 1).coerceAtMost(MAX_WINDOW)
                    }
                } else {
                    closeAcked = true
                }
            }
        }
    }

    private fun processNewData(message: DataPacket) {
        if (receiveBuffer.size >= MAX_RECEIVE_BUFFER) {
            return
        }
        var index = 0
        var added = false
        for (item in receiveBuffer) {
            val comp = SequenceNumber.distance16(message.seqNo, item.seqNo)
            if (comp == 0) {
                return
            } else if (comp > 0) {
                receiveBuffer.add(index, message)
                added = true
                needAck = true
                break
            }
            ++index
        }
        if (!added) {
            receiveBuffer.add(message)
            needAck = true
        }
        updateReceiveAckSeqNo()
    }

    fun processMessage(message: DataPacket, now: Instant) {
        if (message.sessionId != sessionId) {
            shutdownSession()
            return
        }
        val packetType = message.packetType
        log.info(
            "receive $packetType message seq ${message.seqNo} ack ${message.ackSeqNo}  sack ${
                message.selectiveAck.toString(
                    2
                )
            } window ${message.receiveWindowSize}"
        )
        if (packetType == DataPacket.DataPacketType.RESET) {
            updateState(message, now)
            return
        }
        val ackComp = SequenceNumber.distance16(sendAckSeqNo, message.ackSeqNo)
        val sendComp = SequenceNumber.distance16(sendSeqNo, message.ackSeqNo)
        if (ackComp < -MAX_WINDOW || (sendComp > 0)) {
            shutdownSession()
            return
        }
        updateState(message, now)
        if (packetType == DataPacket.DataPacketType.NORMAL
            || packetType == DataPacket.DataPacketType.ACK
        ) {
            receiveWindowSize = message.receiveWindowSize
        }
        if (message.isAck && ackComp == 0 && sendBuffer.isNotEmpty()) {
            ++dupAckCount
        }
        if (ackComp > 0) { // only process innovations
            updateSendAckSeqNo(message, packetType, now)
        }
        val distance = SequenceNumber.distance16(receiveAckSeqNo, message.seqNo)
        if (distance < -MAX_WINDOW || distance > MAX_WINDOW) {
            shutdownSession()
            return
        }
        if (distance < 0) {
            needAck = true
            return
        }
        if (packetType == DataPacket.DataPacketType.CLOSE) {
            updateReceiveAckSeqNo()
            if (message.seqNo == receiveAckSeqNo) {
                closeReceived = true
                receiveAckSeqNo = SequenceNumber.increment16(receiveAckSeqNo)
            }
            return
        }
        if (message.isAck) {
            return
        }
        processNewData(message)
    }
}