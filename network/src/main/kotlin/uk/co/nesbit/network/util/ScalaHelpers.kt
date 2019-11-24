package uk.co.nesbit.network.util

import akka.actor.AbstractActorWithTimers
import akka.actor.Props
import akka.event.Logging
import akka.event.LoggingAdapter
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration
import scala.jdk.javaapi.CollectionConverters
import java.util.concurrent.TimeUnit

fun Int.seconds(): FiniteDuration =
    Duration.create(this.toLong(), TimeUnit.SECONDS)


fun Long.millis(): FiniteDuration =
    Duration.create(this, TimeUnit.MILLISECONDS)

abstract class AbstractActorWithLoggingAndTimers() : AbstractActorWithTimers() {
    private var _log: LoggingAdapter? = null
    protected fun log(): LoggingAdapter {
        if (_log == null) {
            _log = object : LoggingAdapter {
                private var logger: Logger = LoggerFactory.getLogger(self.toString())
                override fun isErrorEnabled(): Boolean = logger.isErrorEnabled

                override fun isWarningEnabled(): Boolean = logger.isWarnEnabled

                override fun isInfoEnabled(): Boolean = logger.isInfoEnabled

                override fun isDebugEnabled(): Boolean = logger.isDebugEnabled

                override fun notifyError(message: String?) {
                    logger.error(message)
                }

                override fun notifyError(cause: Throwable?, message: String?) {
                    logger.error(message, cause)
                }

                override fun notifyWarning(message: String?) {
                    logger.warn(message)
                }

                override fun notifyInfo(message: String?) {
                    logger.info(message)
                }

                override fun notifyDebug(message: String?) {
                    logger.debug(message)
                }
            }
        }
        return _log!!
    }
}

// TODO This works around a stupid error highlighting bug in Idea, hopefully will get fixed
fun createProps(clazz: Class<*>, vararg inputs: Any): Props {
    return Props.create(clazz, CollectionConverters.asScala(inputs.iterator()).toSeq())
}