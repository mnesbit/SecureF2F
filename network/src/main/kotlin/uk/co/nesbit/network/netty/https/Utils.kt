package uk.co.nesbit.network.netty.https

import io.netty.buffer.Unpooled
import io.netty.handler.codec.http.*
import io.netty.util.concurrent.DefaultThreadFactory
import java.time.Duration
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

// Creates a [ThreadPoolExecutor] which will use a maximum of [maxPoolSize] threads at any given time and will by default idle down to 0
// threads.
internal fun namedThreadPoolExecutor(
    maxPoolSize: Int,
    corePoolSize: Int = 0,
    idleKeepAlive: Duration = Duration.ofSeconds(30),
    workQueue: BlockingQueue<Runnable> = LinkedBlockingQueue(),
    poolName: String = "pool",
    daemonThreads: Boolean = false,
    threadPriority: Int = Thread.NORM_PRIORITY
): ThreadPoolExecutor {
    return ThreadPoolExecutor(
        corePoolSize,
        maxPoolSize,
        idleKeepAlive.toNanos(),
        TimeUnit.NANOSECONDS,
        workQueue,
        DefaultThreadFactory(poolName, daemonThreads, threadPriority)
    )
}

internal fun createResponse(message: ByteArray?, status: HttpResponseStatus): HttpResponse {
    val content = if (message != null) Unpooled.copiedBuffer(message) else Unpooled.EMPTY_BUFFER
    return DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status, content).apply {
        headers().set(HttpHeaderNames.CONTENT_TYPE, HttpHeaderValues.APPLICATION_JSON)
            .setInt(HttpHeaderNames.CONTENT_LENGTH, content().readableBytes())
            .set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE)
    }
}