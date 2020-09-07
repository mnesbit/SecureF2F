package uk.co.nesbit.network

import org.junit.Assert.assertArrayEquals
import org.junit.Test
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper.Companion.MAX_RECEIVE_BUFFER
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper.Companion.MAX_SEND_BUFFER
import uk.co.nesbit.network.treeEngine.SlidingWindowHelper.Companion.START_WINDOW
import java.time.Clock
import java.time.Instant
import java.util.*
import kotlin.test.assertEquals

class SlidingWindowTest {
    private fun getPacket(i: Int): ByteArray {
        return i.toString().toByteArray(Charsets.UTF_8)
    }

    @Test
    fun `transfer packets one way no drop`() {
        val slide1 = SlidingWindowHelper(1L)
        val slide2 = SlidingWindowHelper(1L)
        for (i in 0 until MAX_SEND_BUFFER) {
            assertEquals(true, slide1.sendPacket(getPacket(i)))
        }
        assertEquals(false, slide1.sendPacket(getPacket(11)))
        val toSend1 = slide1.pollForTransmit(Instant.ofEpochSecond(1L))
        assertEquals(START_WINDOW, toSend1.size)
        var seq = 0
        for (packet in toSend1) {
            assertEquals(1L, packet.sessionId)
            assertEquals(MAX_RECEIVE_BUFFER, packet.receiveWindowSize)
            assertEquals(seq++, packet.seqNo)
            assertEquals(0, packet.ackSeqNo)
            slide2.processMessage(packet, Instant.ofEpochSecond(2L))
        }
        val received1 = slide2.pollReceivedPackets()
        assertEquals(START_WINDOW, received1.size)
        for (i in received1.indices) {
            assertArrayEquals(getPacket(i), received1[i])
        }
        val reply1 = slide2.pollForTransmit(Instant.ofEpochSecond(3L))
        assertEquals(1, reply1.size)
        assertEquals(START_WINDOW, reply1.single().ackSeqNo)
        assertEquals(0, reply1.single().seqNo)
        val toSend2 = slide1.pollForTransmit(Instant.ofEpochSecond(4L))
        assertEquals(1, toSend2.size) // ack packet only
        assertEquals(true, toSend2.single().isAck)
        slide1.processMessage(reply1.first(), Instant.ofEpochSecond(5L))
        val toSend3 = slide1.pollForTransmit(Instant.ofEpochSecond(6L))
        assertEquals(MAX_SEND_BUFFER - toSend1.size, toSend3.size)
        for (packet in toSend3) {
            assertEquals(1L, packet.sessionId)
            assertEquals(MAX_RECEIVE_BUFFER, packet.receiveWindowSize)
            assertEquals(seq++, packet.seqNo)
            assertEquals(0, packet.ackSeqNo)
            slide2.processMessage(packet, Instant.ofEpochSecond(7L))
        }
        val reply2 = slide2.pollForTransmit(Instant.ofEpochSecond(8L))
        assertEquals(1, reply2.size)
        assertEquals(MAX_SEND_BUFFER, reply2.single().ackSeqNo)
        slide1.processMessage(reply2.first(), Instant.ofEpochSecond(9L))
        val toSend4 = slide1.pollForTransmit(Instant.ofEpochSecond(10L))
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
}