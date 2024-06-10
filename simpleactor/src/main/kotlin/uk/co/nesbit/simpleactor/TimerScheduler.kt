package uk.co.nesbit.simpleactor

import java.time.Duration

interface TimerScheduler {
    fun cancel(key: Any)
    fun cancelAll()
    fun isTimerActive(key: Any): Boolean
    fun startSingleTimer(key: Any, msg: Any, timeout: Duration)
    fun startTimerAtFixedRate(key: Any, msg: Any, interval: Duration) =
        startTimerAtFixedRate(key, msg, interval, interval)

    fun startTimerAtFixedRate(key: Any, msg: Any, initialDelay: Duration, interval: Duration)
    fun startTimerAtFixedDelay(key: Any, msg: Any, interval: Duration) =
        startTimerAtFixedDelay(key, msg, interval, interval)

    fun startTimerAtFixedDelay(key: Any, msg: Any, initialDelay: Duration, interval: Duration)
}

fun Long.millis(): Duration = Duration.ofMillis(this)
