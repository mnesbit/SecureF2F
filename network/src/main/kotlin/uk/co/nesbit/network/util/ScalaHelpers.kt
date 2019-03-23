package uk.co.nesbit.network.util

import akka.actor.AbstractActorWithTimers
import akka.event.Logging
import akka.event.LoggingAdapter
import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration
import java.util.concurrent.TimeUnit

fun Int.seconds(): FiniteDuration =
    Duration.create(this.toLong(), TimeUnit.SECONDS)


fun Long.millis(): FiniteDuration =
    Duration.create(this, TimeUnit.MILLISECONDS)

abstract class AbstractActorWithLoggingAndTimers() : AbstractActorWithTimers() {
    private var _log: LoggingAdapter? = null
    protected fun log(): LoggingAdapter {
        if (_log == null) {
            _log = Logging.getLogger(getContext().getSystem(), this)
//            _log = object : LoggingAdapter {
//                val label = self.toString()
//
//                override fun isErrorEnabled(): Boolean = true
//
//                override fun isWarningEnabled(): Boolean = true
//
//                override fun isInfoEnabled(): Boolean = true
//
//                override fun isDebugEnabled(): Boolean = false
//
//                override fun notifyError(message: String?) {
//                    println("$label $message")
//                }
//
//                override fun notifyError(cause: Throwable?, message: String?) {
//                    println("$label $message")
//                }
//
//                override fun notifyWarning(message: String?) {
//                    println("$label $message")
//                }
//
//                override fun notifyInfo(message: String?) {
//                    println("$label $message")
//                }
//
//                override fun notifyDebug(message: String?) {
//                    println("$label $message")
//                }
//
//            }
        }
        return _log!!
    }

}