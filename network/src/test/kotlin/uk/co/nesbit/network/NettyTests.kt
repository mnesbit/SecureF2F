package uk.co.nesbit.network

import org.junit.jupiter.api.Test
import uk.co.nesbit.network.netty.tcp.*
import java.net.BindException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.UnresolvedAddressException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NettyTests {
    @Test
    fun `Simple server start stop`() {
        val server = TcpServer(InetSocketAddress("0.0.0.0", 10000), TcpServerConfig(true))
        val msgCount = AtomicInteger(0)
        val openCount = AtomicInteger(0)
        val closeCount = AtomicInteger(0)
        val serverEvents = server.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onConnected $localAddress, $remoteAddress")
                    openCount.getAndIncrement()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onDisconnected $localAddress, $remoteAddress")
                    closeCount.getAndIncrement()
                }
            }
        )

        val serverMessages = server.registerMessageListener { l, r, msg ->
            println("Server onMessage $l, $r, $msg")
            msgCount.getAndIncrement()
        }
        server.start()

        server.close()
        serverEvents.close()
        serverMessages.close()
        assertEquals(0, openCount.get())
        assertEquals(0, closeCount.get())
        assertEquals(0, msgCount.get())
    }

    @Test
    fun `server bind failure`() {
        val server = TcpServer(InetSocketAddress("rubbish", 10000), TcpServerConfig(true))
        assertFailsWith<UnresolvedAddressException> {
            server.start()
        }
        val server2 = TcpServer(InetSocketAddress("localhost", 10000), TcpServerConfig(true))
        server2.start()
        val server3 = TcpServer(InetSocketAddress("localhost", 10000), TcpServerConfig(true))
        assertFailsWith<BindException> {
            server3.start()
        }
        server2.close()
    }

    @Test
    fun `Simple client server`() {
        val server = TcpServer(InetSocketAddress("0.0.0.0", 10000), TcpServerConfig(true))
        val msgCount = AtomicInteger(0)
        val echoCount = AtomicInteger(0)
        val openCount = AtomicInteger(0)
        val closeCount = AtomicInteger(0)
        val errorCount = AtomicInteger(0)
        val serverEvents = server.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onConnected $localAddress, $remoteAddress")
                    openCount.getAndIncrement()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onDisconnected $localAddress, $remoteAddress")
                    closeCount.getAndIncrement()
                }
            }
        )

        val serverMessages = server.registerMessageListener { localAddress, remoteAddress, msg ->
            println("Server onMessage $localAddress, $remoteAddress, ${msg.toString(Charsets.UTF_8)}")
            val count = msgCount.incrementAndGet()
            if (msg.toString(Charsets.UTF_8) != "Msg$count") errorCount.getAndIncrement()
            server.sendData(msg, remoteAddress)
        }
        server.start()

        val client = TcpClient(InetSocketAddress("localhost", 10000), TcpClientConfig(trace = true))
        val clientEvents = client.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("client onConnected $localAddress, $remoteAddress")
                    client.sendData("Msg2".toByteArray(Charsets.UTF_8))
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("client onDisconnected $localAddress, $remoteAddress")
                }
            }
        )

        val clientMessages = client.registerMessageListener { localAddress, remoteAddress, msg ->
            println("client onMessage $localAddress, $remoteAddress, ${msg.toString(Charsets.UTF_8)}")
            val count = echoCount.incrementAndGet()
            if (msg.toString(Charsets.UTF_8) != "Msg$count") errorCount.incrementAndGet()
        }
        client.sendData("Msg1".toByteArray(Charsets.UTF_8))
        client.start()
        while (echoCount.get() < 2) {
            Thread.sleep(100)
        }
        clientMessages.close()
        clientEvents.close()
        client.close()
        serverEvents.close()
        serverMessages.close()
        server.close()
        assertEquals(1, openCount.get())
        assertEquals(1, closeCount.get())
        assertEquals(2, msgCount.get())
        assertEquals(2, echoCount.get())
        assertEquals(0, errorCount.get())
    }

    @Test
    fun `client server closed at server`() {
        val server = TcpServer(InetSocketAddress("0.0.0.0", 10000), TcpServerConfig(true))
        val serverOpenCount = AtomicInteger(0)
        val serverCloseCount = AtomicInteger(0)
        val clientOpenCount = AtomicInteger(0)
        val clientCloseCount = AtomicInteger(0)
        val serverEvents = server.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onConnected $localAddress, $remoteAddress")
                    serverOpenCount.getAndIncrement()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onDisconnected $localAddress, $remoteAddress")
                    serverCloseCount.getAndIncrement()
                }
            }
        )
        server.start()

        val client = TcpClient(InetSocketAddress("localhost", 10000), TcpClientConfig(trace = true))
        val clientEvents = client.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("client onConnected $localAddress, $remoteAddress")
                    clientOpenCount.incrementAndGet()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    clientCloseCount.incrementAndGet()
                }
            }
        )

        client.sendData("Msg1".toByteArray(Charsets.UTF_8))
        client.start()
        while (clientOpenCount.get() != 1) {
            Thread.sleep(100L)
        }
        assertEquals(1, serverOpenCount.get())
        assertEquals(0, serverCloseCount.get())
        assertEquals(1, clientOpenCount.get())
        assertEquals(0, clientCloseCount.get())
        server.close()
        serverEvents.close()
        assertEquals(1, serverOpenCount.get())
        assertEquals(1, serverCloseCount.get())
        assertEquals(1, clientOpenCount.get())
        assertEquals(1, clientCloseCount.get())
        client.close()
        clientEvents.close()
        assertEquals(1, serverOpenCount.get())
        assertEquals(1, serverCloseCount.get())
        assertEquals(1, clientOpenCount.get())
        assertEquals(1, clientCloseCount.get())
    }

    @Test
    fun `client server closed at client`() {
        val server = TcpServer(InetSocketAddress("0.0.0.0", 10000), TcpServerConfig(true))
        val serverOpenCount = AtomicInteger(0)
        val serverCloseCount = AtomicInteger(0)
        val clientOpenCount = AtomicInteger(0)
        val clientCloseCount = AtomicInteger(0)
        val serverEvents = server.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onConnected $localAddress, $remoteAddress")
                    serverOpenCount.getAndIncrement()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("Server onDisconnected $localAddress, $remoteAddress")
                    serverCloseCount.getAndIncrement()
                }
            }
        )
        server.start()

        val client = TcpClient(InetSocketAddress("localhost", 10000), TcpClientConfig(trace = true))
        val clientEvents = client.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    println("client onConnected $localAddress, $remoteAddress")
                    clientOpenCount.incrementAndGet()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    clientCloseCount.incrementAndGet()
                }
            }
        )

        client.sendData("Msg1".toByteArray(Charsets.UTF_8))
        client.start()
        while (clientOpenCount.get() != 1) {
            Thread.sleep(100L)
        }
        assertEquals(1, serverOpenCount.get())
        assertEquals(0, serverCloseCount.get())
        assertEquals(1, clientOpenCount.get())
        assertEquals(0, clientCloseCount.get())
        client.close()
        clientEvents.close()
        assertEquals(1, serverOpenCount.get())
        assertEquals(1, serverCloseCount.get())
        assertEquals(1, clientOpenCount.get())
        assertEquals(1, clientCloseCount.get())
        server.close()
        serverEvents.close()
        assertEquals(1, serverOpenCount.get())
        assertEquals(1, serverCloseCount.get())
        assertEquals(1, clientOpenCount.get())
        assertEquals(1, clientCloseCount.get())
    }

    @Test
    fun `Lots of messages client to server`() {
        val N = 10000
        val MessageSize = 10000
        val server = TcpServer(InetSocketAddress("0.0.0.0", 10000), TcpServerConfig(false))
        server.start()
        val messageDone = CountDownLatch(N)
        var count = 0
        val errorCount = AtomicInteger(0)
        val serverMessages = server.registerMessageListener { localAddress, remoteAddress, msg ->
            if (msg.size != MessageSize) errorCount.incrementAndGet()
            val readBuf = ByteBuffer.wrap(msg)
            if (readBuf.getInt() != count++) errorCount.incrementAndGet()
            messageDone.countDown()
        }
        val client = TcpClient(InetSocketAddress("localhost", 10000), TcpClientConfig(trace = false))
        val started = CountDownLatch(1)
        val clientEvents = client.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    started.countDown()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                }
            }
        )
        client.start()
        started.await()
        for (i in 0 until N) {
            val bytes = ByteArray(MessageSize)
            val buf = ByteBuffer.wrap(bytes)
            buf.putInt(i)
            client.sendData(bytes)
        }
        messageDone.await()
        client.close()
        clientEvents.close()
        server.close()
        serverMessages.close()
        assertEquals(0, errorCount.get())
        assertEquals(N, count)
    }

    @Test
    fun `Lots of messages server to client`() {
        val N = 10000
        val MessageSize = 10000
        val server = TcpServer(InetSocketAddress("0.0.0.0", 10000), TcpServerConfig(false))
        server.start()
        val started = CountDownLatch(1)
        var clientAddress: InetSocketAddress? = null
        val serverEvents = server.registerConnectListener(
            object : TcpConnectListener {
                override fun onConnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                    clientAddress = remoteAddress
                    started.countDown()
                }

                override fun onDisconnected(localAddress: InetSocketAddress, remoteAddress: InetSocketAddress) {
                }
            }
        )
        val messageDone = CountDownLatch(N)
        var count = 0
        val errorCount = AtomicInteger(0)
        val client = TcpClient(InetSocketAddress("localhost", 10000), TcpClientConfig(trace = false))
        val clientMessages = client.registerMessageListener { localAddress, remoteAddress, msg ->
            if (msg.size != MessageSize) errorCount.incrementAndGet()
            val readBuf = ByteBuffer.wrap(msg)
            if (readBuf.getInt() != count++) errorCount.incrementAndGet()
            messageDone.countDown()
        }
        client.start()
        started.await()
        for (i in 0 until N) {
            val bytes = ByteArray(MessageSize)
            val buf = ByteBuffer.wrap(bytes)
            buf.putInt(i)
            server.sendData(bytes, clientAddress!!)
        }
        messageDone.await()
        server.close()
        serverEvents.close()
        client.close()
        clientMessages.close()
        assertEquals(0, errorCount.get())
        assertEquals(N, count)
    }

}