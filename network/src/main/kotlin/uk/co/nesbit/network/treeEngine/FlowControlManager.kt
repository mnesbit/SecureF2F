package uk.co.nesbit.network.treeEngine

import uk.co.nesbit.network.api.Message
import uk.co.nesbit.network.api.tree.AckMessage
import uk.co.nesbit.network.api.tree.OneHopMessage

class FlowControlManager {
    companion object {
        private const val MIN_WINDOW_SIZE = 3
        private const val MAX_BUFFERED_MESSAGES = 5
    }

    private var seqNum: Int = 0
    private var ackSeqNum: Int = -1
    private var confirmedSeqNum: Int = 0
    private var ackSent: Int = -1
    private var linkCapacity: Int = 2 * MIN_WINDOW_SIZE
    private val bufferedMessages = java.util.ArrayDeque<Message>()

    fun createOneHopMessage(message: Message): OneHopMessage {
        val oneHopMessage = OneHopMessage.createOneHopMessage(seqNum++, ackSeqNum, message)
        ackSent = ackSeqNum
        return oneHopMessage
    }

    fun increaseWindow() {
        linkCapacity++
    }

    fun reduceWindow() {
        linkCapacity = Integer.max((linkCapacity + 1) / 2, MIN_WINDOW_SIZE)
    }

    fun clearBuffer() {
        bufferedMessages.clear()
    }

    fun ackMessage(oneHopMessage: OneHopMessage): List<OneHopMessage> {
        ackSeqNum = oneHopMessage.seqNum
        confirmedSeqNum = oneHopMessage.ackSeqNum
        increaseWindow()
        return sendAck()
    }

    fun sendAck(): List<OneHopMessage> {
        val messagesToSend = mutableListOf<OneHopMessage>()
        while (confirmedSeqNum + linkCapacity >= seqNum
            && bufferedMessages.isNotEmpty()
        ) {
            messagesToSend += createOneHopMessage(bufferedMessages.poll())
        }
        if (ackSeqNum - ackSent >= MIN_WINDOW_SIZE) {
            messagesToSend += createOneHopMessage(AckMessage())
            --seqNum
        }
        return messagesToSend
    }

    fun isCongested(headRoom: Int, messageToBuffer: Message?): Boolean {
        if (confirmedSeqNum + linkCapacity + headRoom < seqNum) {
            if (messageToBuffer != null) {
                bufferedMessages.offer(messageToBuffer)
                if (bufferedMessages.size > MAX_BUFFERED_MESSAGES) {
                    bufferedMessages.poll()
                }
            }
            return true
        }
        return false
    }
}