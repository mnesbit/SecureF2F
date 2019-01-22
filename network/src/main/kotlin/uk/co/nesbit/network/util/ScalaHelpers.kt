package uk.co.nesbit.network.util

import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration
import java.util.concurrent.TimeUnit

fun Int.seconds(): FiniteDuration =
    Duration.create(this.toLong(), TimeUnit.SECONDS)