package uk.co.nesbit.network.util

import com.squareup.moshi.FromJson
import com.squareup.moshi.ToJson
import java.time.Instant
import java.time.format.DateTimeFormatter

object InstantTimeAdapter {
    private val FORMATTER = DateTimeFormatter.ISO_INSTANT

    @ToJson
    fun toJson(value: Instant): String {
        return FORMATTER.format(value)
    }

    @FromJson
    fun fromJson(value: String): Instant {
        return Instant.from(FORMATTER.parse(value))
    }
}