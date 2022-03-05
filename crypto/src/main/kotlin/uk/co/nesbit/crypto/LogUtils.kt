package uk.co.nesbit.crypto

import org.slf4j.Logger
import org.slf4j.LoggerFactory

inline fun <reified T : Any> loggerFor(): Logger = LoggerFactory.getLogger(T::class.java)

fun Any.contextLogger(): Logger = LoggerFactory.getLogger(
    javaClass.enclosingClass ?: throw java.lang.IllegalArgumentException("Should be used on companion object")
)

inline fun Logger.debug(msg: () -> String) {
    if (isDebugEnabled) debug(msg())
}

inline fun Logger.trace(msg: () -> String) {
    if (isTraceEnabled) trace(msg())
}