package uk.co.nesbit.simpleactor.impl

import uk.co.nesbit.simpleactor.ActorRef
import uk.co.nesbit.simpleactor.TimerScheduler
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

internal class TimerSchedulerImpl(
    private val timerService: ScheduledExecutorService,
    private val self: ActorRef
) : TimerScheduler {
    private val timers = ConcurrentHashMap<Any, ScheduledFuture<*>>()

    override fun cancel(key: Any) {
        timers.remove(key)?.cancel(false)
    }

    override fun cancelAll() {
        for (timer in timers) {
            timer.value.cancel(false)
        }
        timers.clear()
    }

    override fun isTimerActive(key: Any): Boolean {
        val timer = timers[key] ?: return false
        return timer.isDone
    }

    override fun startSingleTimer(key: Any, msg: Any, timeout: Duration) {
        cancel(key)
        timers[key] = timerService.schedule(
            {
                self.tell(msg, self)
            },
            timeout.toMillis(),
            TimeUnit.MILLISECONDS
        )
    }

    override fun startTimerAtFixedRate(key: Any, msg: Any, initialDelay: Duration, interval: Duration) {
        cancel(key)
        timers[key] = timerService.scheduleAtFixedRate(
            {
                self.tell(msg, self)
            },
            initialDelay.toMillis(),
            interval.toMillis(),
            TimeUnit.MILLISECONDS
        )
    }

    override fun startTimerAtFixedDelay(key: Any, msg: Any, initialDelay: Duration, interval: Duration) {
        cancel(key)
        timers[key] = timerService.scheduleWithFixedDelay(
            {
                self.tell(msg, self)
            },
            initialDelay.toMillis(),
            interval.toMillis(),
            TimeUnit.MILLISECONDS
        )
    }
}