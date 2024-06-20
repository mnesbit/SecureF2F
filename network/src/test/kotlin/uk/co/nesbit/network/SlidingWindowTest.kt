package uk.co.nesbit.network

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import uk.co.nesbit.network.treeEngine.DataPacket
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper.Companion.MAX_RECEIVE_BUFFER
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper.Companion.MAX_SEND_BUFFER
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper.Companion.START_WINDOW
import java.time.Clock
import java.time.Instant
import java.util.*

// prevent gradle crashing from too much console logging
class SlidingWindowTest {
    private fun getPacket(i: Int): ByteArray {
        return i.toString().toByteArray(Charsets.UTF_8)
    }

    @Test
    fun `handshake test`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val eventTime = Instant.ofEpochSecond(1L)
        val openPacket1 = slide1.pollForTransmit(eventTime)
        assertEquals(false, slide1.isEstablished())
        assertEquals(1, openPacket1.size)
        assertEquals(DataPacket.DataPacketType.OPEN, openPacket1.single().packetType)
        slide2.processMessage(openPacket1.single(), eventTime)
        assertEquals(false, slide2.isEstablished())
        val openPacket2 = slide2.pollForTransmit(eventTime)
        assertEquals(false, slide2.isEstablished())
        assertEquals(1, openPacket2.size)
        assertEquals(DataPacket.DataPacketType.OPEN_ACK, openPacket2.single().packetType)
        slide1.processMessage(openPacket2.single(), eventTime)
        assertEquals(true, slide1.isEstablished())
        val openPacket3 = slide1.pollForTransmit(eventTime)
        assertEquals(1, openPacket3.size)
        assertEquals(DataPacket.DataPacketType.ACK, openPacket3.single().packetType)
        slide2.processMessage(openPacket3.single(), eventTime)
        assertEquals(true, slide2.isEstablished())
        val openPacket4 = slide2.pollForTransmit(eventTime)
        assertEquals(1, openPacket3.size)
        assertEquals(DataPacket.DataPacketType.ACK, openPacket4.single().packetType)
        slide1.processMessage(openPacket4.single(), eventTime)
        assertEquals(true, slide1.isEstablished())
    }

    @Test
    fun `simultaneous open handshake test`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val eventTime = Instant.ofEpochSecond(1L)
        val openPacket1 = slide1.pollForTransmit(eventTime)
        assertEquals(false, slide1.isEstablished())
        assertEquals(1, openPacket1.size)
        assertEquals(DataPacket.DataPacketType.OPEN, openPacket1.single().packetType)
        val openPacket2 = slide2.pollForTransmit(eventTime)
        assertEquals(false, slide2.isEstablished())
        assertEquals(1, openPacket2.size)
        assertEquals(DataPacket.DataPacketType.OPEN, openPacket2.single().packetType)
        slide2.processMessage(openPacket1.single(), eventTime)
        assertEquals(false, slide2.isEstablished())
        slide1.processMessage(openPacket2.single(), eventTime)
        assertEquals(false, slide1.isEstablished())
        val openPacket3 = slide1.pollForTransmit(eventTime)
        assertEquals(false, slide1.isEstablished())
        assertEquals(1, openPacket3.size)
        assertEquals(DataPacket.DataPacketType.OPEN_ACK, openPacket3.single().packetType)
        val openPacket4 = slide2.pollForTransmit(eventTime)
        assertEquals(false, slide2.isEstablished())
        assertEquals(1, openPacket4.size)
        assertEquals(DataPacket.DataPacketType.OPEN_ACK, openPacket4.single().packetType)
        slide2.processMessage(openPacket3.single(), eventTime)
        assertEquals(true, slide2.isEstablished())
        slide1.processMessage(openPacket4.single(), eventTime)
        assertEquals(true, slide1.isEstablished())
        val openPacket5 = slide1.pollForTransmit(eventTime)
        assertEquals(true, slide1.isEstablished())
        assertEquals(1, openPacket5.size)
        assertEquals(DataPacket.DataPacketType.ACK, openPacket5.single().packetType)
        val openPacket6 = slide2.pollForTransmit(eventTime)
        assertEquals(1, openPacket4.size)
        assertEquals(DataPacket.DataPacketType.ACK, openPacket6.single().packetType)
        slide2.processMessage(openPacket5.single(), eventTime)
        assertEquals(true, slide2.isEstablished())
        slide1.processMessage(openPacket6.single(), eventTime)
        assertEquals(true, slide1.isEstablished())
        val openPacket7 = slide1.pollForTransmit(eventTime)
        assertEquals(true, slide1.isEstablished())
        assertEquals(0, openPacket7.size)
        val openPacket8 = slide2.pollForTransmit(eventTime)
        assertEquals(true, slide2.isEstablished())
        assertEquals(0, openPacket8.size)
    }

    @Test
    fun `handshake test with drops`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        var eventTime = Instant.ofEpochSecond(1L)
        slide1.pollForTransmit(eventTime) // get and discard
        eventTime = eventTime.plusMillis(slide1.getNearestDeadline(eventTime))
        val openPacket1 = slide1.pollForTransmit(eventTime)
        assertEquals(false, slide1.isEstablished())
        assertEquals(1, openPacket1.size)
        assertEquals(DataPacket.DataPacketType.OPEN, openPacket1.single().packetType)
        slide2.processMessage(openPacket1.single(), eventTime)
        assertEquals(false, slide2.isEstablished())
        slide2.pollForTransmit(eventTime) // get and discard
        eventTime = eventTime.plusMillis(slide2.getNearestDeadline(eventTime))
        val openPacket2 = slide2.pollForTransmit(eventTime)
        assertEquals(1, openPacket2.size)
        assertEquals(DataPacket.DataPacketType.OPEN_ACK, openPacket2.single().packetType)
        slide1.processMessage(openPacket2.single(), eventTime)
        assertEquals(true, slide1.isEstablished())
        slide1.pollForTransmit(eventTime) // get and discard
        eventTime = eventTime.plusMillis(slide2.getNearestDeadline(eventTime))
        val openPacket3 = slide2.pollForTransmit(eventTime)
        assertEquals(1, openPacket3.size)
        assertEquals(DataPacket.DataPacketType.OPEN_ACK, openPacket3.single().packetType)
        slide1.processMessage(openPacket3.single(), eventTime)
        val openPacket4 = slide1.pollForTransmit(eventTime)
        assertEquals(1, openPacket4.size)
        assertEquals(DataPacket.DataPacketType.ACK, openPacket4.single().packetType)
        slide2.processMessage(openPacket4.single(), eventTime)
        assertEquals(true, slide2.isEstablished())
    }

    @Test
    fun `transfer packets one way no drop`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        for (i in 0 until MAX_SEND_BUFFER) {
            assertEquals(true, slide1.sendPacket(getPacket(i)))
        }
        assertEquals(false, slide1.sendPacket(getPacket(11)))
        val openPacket1 = slide1.pollForTransmit(Instant.ofEpochMilli(1L))
        assertEquals(false, slide1.isEstablished())
        assertEquals(false, slide1.isTerminated())
        assertEquals(1, openPacket1.size)
        assertEquals(DataPacket.DataPacketType.OPEN, openPacket1.single().packetType)
        assertEquals(true, openPacket1.single().isAck)
        slide2.processMessage(openPacket1.single(), Instant.ofEpochMilli(2L))
        assertEquals(0, slide2.pollReceivedPackets().size)
        assertEquals(false, slide1.isEstablished())
        assertEquals(false, slide1.isTerminated())
        val openPacket2 = slide2.pollForTransmit(Instant.ofEpochMilli(3L))
        assertEquals(1, openPacket2.size)
        assertEquals(DataPacket.DataPacketType.OPEN_ACK, openPacket2.single().packetType)
        assertEquals(true, openPacket2.single().isAck)
        slide1.processMessage(openPacket2.single(), Instant.ofEpochMilli(4L))
        assertEquals(true, slide1.isEstablished())
        assertEquals(false, slide1.isTerminated())
        val toSend1 = slide1.pollForTransmit(Instant.ofEpochMilli(5L))
        assertEquals(START_WINDOW, toSend1.size)
        var seq = 0
        for (packet in toSend1) {
            assertEquals(1L, packet.sessionId)
            assertEquals(MAX_RECEIVE_BUFFER, packet.receiveWindowSize)
            assertEquals(seq++, packet.seqNo)
            assertEquals(0, packet.ackSeqNo)
            slide2.processMessage(packet, Instant.ofEpochMilli(6L))
        }
        assertEquals(true, slide2.isEstablished())
        assertEquals(false, slide2.isTerminated())
        val received1 = slide2.pollReceivedPackets()
        assertEquals(START_WINDOW, received1.size)
        for (i in received1.indices) {
            assertArrayEquals(getPacket(i), received1[i])
        }
        val reply1 = slide2.pollForTransmit(Instant.ofEpochMilli(7L))
        assertEquals(1, reply1.size)
        assertEquals(START_WINDOW, reply1.single().ackSeqNo)
        assertEquals(0, reply1.single().seqNo)
        val toSend2 = slide1.pollForTransmit(Instant.ofEpochMilli(8L))
        assertEquals(1, toSend2.size) // ack packet only
        assertEquals(true, toSend2.single().isAck)
        slide1.processMessage(reply1.first(), Instant.ofEpochMilli(9L))
        val toSend3 = slide1.pollForTransmit(Instant.ofEpochMilli(10L))
        assertEquals(MAX_SEND_BUFFER - toSend1.size, toSend3.size)
        for (packet in toSend3) {
            assertEquals(1L, packet.sessionId)
            assertEquals(MAX_RECEIVE_BUFFER, packet.receiveWindowSize)
            assertEquals(seq++, packet.seqNo)
            assertEquals(0, packet.ackSeqNo)
            slide2.processMessage(packet, Instant.ofEpochMilli(11L))
        }
        val reply2 = slide2.pollForTransmit(Instant.ofEpochMilli(12L))
        assertEquals(1, reply2.size)
        assertEquals(MAX_SEND_BUFFER, reply2.single().ackSeqNo)
        slide1.processMessage(reply2.first(), Instant.ofEpochMilli(13L))
        val toSend4 = slide1.pollForTransmit(Instant.ofEpochMilli(14L))
        assertEquals(0, toSend4.size)
    }

    @Test
    fun `Simple transfer of many packets no drop`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 1000000) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received.isEmpty() && send.isEmpty() && reply.isEmpty()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `Simple transfer of many packets with drop and dup`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 1000000) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                    slide2.processMessage(item, Clock.systemUTC().instant())
                }
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received.isEmpty() && send.isEmpty() && reply.isEmpty()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `Simple transfer of many packets with reorder and drop and dup`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 1000000) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            val shuffled = send.shuffled(rand)
            for (item in shuffled) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                    slide2.processMessage(item, Clock.systemUTC().instant())
                }
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received.isEmpty() && send.isEmpty() && reply.isEmpty()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `Simple transfer of many packets with reorder`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 1000000) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            val shuffled = send.shuffled(rand)
            for (item in shuffled) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received.isEmpty() && send.isEmpty() && reply.isEmpty()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `Bidirectional transfer of many packets with reorder`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq1 = 0
        var receiveSeq1 = 0
        var sendSeq2 = 0
        var receiveSeq2 = 0
        for (i in 0 until 1000000) {
            val numAdd1 = rand.nextInt(20)
            for (j in 0 until numAdd1) {
                if (slide1.sendPacket(getPacket(sendSeq1))) {
                    ++sendSeq1
                }
            }
            val numAdd2 = rand.nextInt(20)
            for (j in 0 until numAdd2) {
                if (slide2.sendPacket(getPacket(sendSeq2))) {
                    ++sendSeq2
                }
            }
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            val shuffled1 = send1.shuffled(rand)
            for (item in shuffled1) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val shuffled2 = send2.shuffled(rand)
            for (item in shuffled2) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        while (true) {
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            for (item in send1) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            for (item in send2) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received1.isEmpty()
                && received2.isEmpty()
                && send1.isEmpty()
                && send2.isEmpty()
            ) {
                break
            }
        }
        assertEquals(sendSeq1, receiveSeq2)
        assertEquals(sendSeq2, receiveSeq1)
    }

    @Test
    fun `Bidirectional transfer of many packets with reorder dup and drop`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq1 = 0
        var receiveSeq1 = 0
        var sendSeq2 = 0
        var receiveSeq2 = 0
        for (i in 0 until 1000000) {
            val numAdd1 = rand.nextInt(20)
            for (j in 0 until numAdd1) {
                if (slide1.sendPacket(getPacket(sendSeq1))) {
                    ++sendSeq1
                }
            }
            val numAdd2 = rand.nextInt(20)
            for (j in 0 until numAdd2) {
                if (slide2.sendPacket(getPacket(sendSeq2))) {
                    ++sendSeq2
                }
            }
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            val shuffled1 = send1.shuffled(rand)
            for (item in shuffled1) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                    slide2.processMessage(item, Clock.systemUTC().instant())
                }
            }
            val shuffled2 = send2.shuffled(rand)
            for (item in shuffled2) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide1.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide1.processMessage(item, Clock.systemUTC().instant())
                    slide1.processMessage(item, Clock.systemUTC().instant())
                }
            }
        }
        while (true) {
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            for (item in send1) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            for (item in send2) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received1.isEmpty()
                && received2.isEmpty()
                && send1.isEmpty()
                && send2.isEmpty()
            ) {
                break
            }
        }
        assertEquals(sendSeq1, receiveSeq2)
        assertEquals(sendSeq2, receiveSeq1)
    }

    @Test
    fun `Bidirectional test without SACK`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq1 = 0
        var receiveSeq1 = 0
        var sendSeq2 = 0
        var receiveSeq2 = 0
        for (i in 0 until 100000) {
            val numAdd1 = rand.nextInt(20)
            for (j in 0 until numAdd1) {
                if (slide1.sendPacket(getPacket(sendSeq1))) {
                    ++sendSeq1
                }
            }
            val numAdd2 = rand.nextInt(20)
            for (j in 0 until numAdd2) {
                if (slide2.sendPacket(getPacket(sendSeq2))) {
                    ++sendSeq2
                }
            }
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            val shuffled1 =
                send1.map { if (it.selectiveAck >= 0) it.copy(selectiveAck = 0xFFFF) else it }.shuffled(rand)
            for (item in shuffled1) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                    slide2.processMessage(item, Clock.systemUTC().instant())
                }
            }
            val shuffled2 =
                send2.map { if (it.selectiveAck >= 0) it.copy(selectiveAck = 0xFFFF) else it }.shuffled(rand)
            for (item in shuffled2) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide1.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide1.processMessage(item, Clock.systemUTC().instant())
                    slide1.processMessage(item, Clock.systemUTC().instant())
                }
            }
        }
        while (true) {
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            for (item in send1) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            for (item in send2) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received1.isEmpty()
                && received2.isEmpty()
                && send1.isEmpty()
                && send2.isEmpty()
            ) {
                break
            }
        }
        assertEquals(sendSeq1, receiveSeq2)
        assertEquals(sendSeq2, receiveSeq1)
    }

    @Test
    fun `Test receive window blocking`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        var sendSeq = 0
        for (i in 0 until 200) {
            while (slide1.sendPacket(getPacket(sendSeq))) {
                ++sendSeq
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        assertEquals(MAX_RECEIVE_BUFFER + MAX_SEND_BUFFER, sendSeq)
        var receiveSeq = 0
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (received.isEmpty() && send.isEmpty() && reply.isEmpty()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `connection close test`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 1000) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        slide1.closeSession(Clock.systemUTC().instant())
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (slide1.isTerminated() && slide2.isTerminated()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `connection close test 2`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 1000) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        slide2.closeSession(Clock.systemUTC().instant())
        while (true) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (slide1.isTerminated() && slide2.isTerminated()) {
                break
            }
        }
        assertEquals(sendSeq, receiveSeq)
    }

    @Test
    fun `Bidirectional close test`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq1 = 0
        var receiveSeq1 = 0
        var sendSeq2 = 0
        var receiveSeq2 = 0
        for (i in 0 until 100000) {
            val numAdd1 = rand.nextInt(20)
            for (j in 0 until numAdd1) {
                if (slide1.sendPacket(getPacket(sendSeq1))) {
                    ++sendSeq1
                }
            }
            val numAdd2 = rand.nextInt(20)
            for (j in 0 until numAdd2) {
                if (slide2.sendPacket(getPacket(sendSeq2))) {
                    ++sendSeq2
                }
            }
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            val shuffled1 = send1.shuffled(rand)
            for (item in shuffled1) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide2.processMessage(item, Clock.systemUTC().instant())
                    slide2.processMessage(item, Clock.systemUTC().instant())
                }
            }
            val shuffled2 = send2.shuffled(rand)
            for (item in shuffled2) {
                val rnd = rand.nextDouble()
                if (rnd < 0.8) {
                    slide1.processMessage(item, Clock.systemUTC().instant())
                } else if (rnd < 0.9) {
                    slide1.processMessage(item, Clock.systemUTC().instant())
                    slide1.processMessage(item, Clock.systemUTC().instant())
                }
            }
        }
        slide1.closeSession(Clock.systemUTC().instant())
        while (true) {
            val send1 = slide1.pollForTransmit(Clock.systemUTC().instant())
            val received1 = slide1.pollReceivedPackets()
            for (item in received1) {
                assertArrayEquals(getPacket(receiveSeq1++), item)
            }
            val send2 = slide2.pollForTransmit(Clock.systemUTC().instant())
            val received2 = slide2.pollReceivedPackets()
            for (item in received2) {
                assertArrayEquals(getPacket(receiveSeq2++), item)
            }
            val shuffled1 = send1.shuffled(rand)
            for (item in shuffled1) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val shuffled2 = send2.shuffled(rand)
            for (item in shuffled2) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
            if (slide1.isTerminated() && slide2.isTerminated()
            ) {
                break
            }
        }
        assertEquals(sendSeq1, receiveSeq2)
        assertEquals(sendSeq2, receiveSeq1)
    }

    @Test
    fun `Broken link test`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 100) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        val slide3 = SlidingWindowHelper(1L)
        while (!slide1.isTerminated() || !slide3.isTerminated()) {
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide3.processMessage(item, Clock.systemUTC().instant())
            }
            val reply = slide3.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
    }

    @Test
    fun `Broken link test2`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        val rand = Random()
        var sendSeq = 0
        var receiveSeq = 0
        for (i in 0 until 100) {
            val numAdd = rand.nextInt(20)
            for (j in 0 until numAdd) {
                if (slide1.sendPacket(getPacket(sendSeq))) {
                    ++sendSeq
                }
            }
            val send = slide1.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
            val received = slide2.pollReceivedPackets()
            for (item in received) {
                assertArrayEquals(getPacket(receiveSeq++), item)
            }
            val reply = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide1.processMessage(item, Clock.systemUTC().instant())
            }
        }
        val slide3 = SlidingWindowHelper(1L)
        while (!slide2.isTerminated() || !slide3.isTerminated()) {
            val send = slide2.pollForTransmit(Clock.systemUTC().instant())
            for (item in send) {
                slide3.processMessage(item, Clock.systemUTC().instant())
            }
            val reply = slide3.pollForTransmit(Clock.systemUTC().instant())
            for (item in reply) {
                slide2.processMessage(item, Clock.systemUTC().instant())
            }
        }
    }

}