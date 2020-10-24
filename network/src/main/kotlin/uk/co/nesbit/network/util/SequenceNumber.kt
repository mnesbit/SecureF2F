package uk.co.nesbit.network.util

// Converted from https://github.com/io7m/jserial/tree/develop/com.io7m.jserial.core/src/main/java/com/io7m/jserial/core
object SequenceNumber {
    @JvmStatic
    private fun signI(
        x: Int
    ): Int {
        return if (x > 0) 1 else -1
    }

    @JvmStatic
    private fun distanceI(
        from: Int,
        to: Int,
        max: Int
    ): Int {
        val lower = Math.min(from, to)
        val higher = Math.max(from, to)

        // Non-serial distance from higher number to max.
        val to_end = max - higher

        // Non-serial distance going directly between inputs.
        val inner = higher - lower

        // Non-serial distance the way that wraps around on the number line.
        val outer = lower + to_end

        // Attempt to find the shortest distance.
        val direction: Int
        if (Math.abs(inner) <= Math.abs(outer)) {
            // The inner route; go right on the number line if to > from.
            direction = signI(to - from)
            return inner * direction
        }

        // The outer route that wraps around; go left on the number line if from < to.
        direction = signI(from - to)
        return outer * direction
    }

    @JvmStatic
    private fun signL(
        x: Long
    ): Long {
        return if (x > 0L) 1L else -1L
    }

    @JvmStatic
    private fun distanceL(
        from: Long,
        to: Long,
        max: Long
    ): Long {
        val lower = Math.min(from, to)
        val higher = Math.max(from, to)

        // Non-serial distance from higher number to 256.
        val to_end = max - higher

        // Non-serial distance going directly between inputs.
        val inner = higher - lower

        // Non-serial distance the way that wraps around on the number line.
        val outer = lower + to_end

        // Attempt to find the shortest distance.
        val direction: Long
        if (Math.abs(inner) <= Math.abs(outer)) {
            // The inner route; go right on the number line if to > from.
            direction = signL(to - from)
            return inner * direction
        }

        // The outer route that wraps around; go left on the number line if from < to.
        direction = signL(from - to)
        return outer * direction
    }

    private const val MAX8 = 256

    @JvmStatic
    fun distance8(from: Int, to: Int): Int {
        return distanceI(from, to, MAX8)
    }

    @JvmStatic
    fun increment8(value: Int): Int {
        if (value < MAX8 - 1) {
            return value + 1
        }
        return 0
    }

    private const val MAX16 = 65536

    @JvmStatic
    fun distance16(from: Int, to: Int): Int {
        return distanceI(from, to, MAX16)
    }

    @JvmStatic
    fun increment16(value: Int): Int {
        if (value < MAX16 - 1) {
            return value + 1
        }
        return 0
    }

    private const val MAX32 = 4294967296L

    private fun int32toULong(from: Int): Long {
        val intermediate = from.toLong()
        return intermediate and 0xFFFFFFFFL
    }

    @JvmStatic
    fun distance32(from: Int, to: Int): Int {
        return distanceL(int32toULong(from), int32toULong(to), MAX32).toInt()
    }

    @JvmStatic
    fun increment32(value: Int): Int {
        if (int32toULong(value) < MAX32 - 1L) {
            return value + 1
        }
        return 0
    }
}