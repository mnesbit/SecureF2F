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
        s0: Int,
        s1: Int,
        max: Int
    ): Int {
        val lower = Math.min(s0, s1)
        val higher = Math.max(s0, s1)

        // Non-serial distance from higher number to max.
        val to_end = max - higher

        // Non-serial distance going directly between inputs.
        val inner = higher - lower

        // Non-serial distance the way that wraps around on the number line.
        val outer = lower + to_end

        // Attempt to find the shortest distance.
        val direction: Int
        if (Math.abs(inner) <= Math.abs(outer)) {
            // The inner route; go right on the number line if s1 > s0.
            direction = signI(s1 - s0)
            return inner * direction
        }

        // The outer route that wraps around; go left on the number line if s0 < s1.
        direction = signI(s0 - s1)
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
        s0: Long,
        s1: Long,
        max: Long
    ): Long {
        val lower = Math.min(s0, s1)
        val higher = Math.max(s0, s1)

        // Non-serial distance from higher number to 256.
        val to_end = max - higher

        // Non-serial distance going directly between inputs.
        val inner = higher - lower

        // Non-serial distance the way that wraps around on the number line.
        val outer = lower + to_end

        // Attempt to find the shortest distance.
        val direction: Long
        if (Math.abs(inner) <= Math.abs(outer)) {
            // The inner route; go right on the number line if s1 > s0.
            direction = signL(s1 - s0)
            return inner * direction
        }

        // The outer route that wraps around; go left on the number line if s0 < s1.
        direction = signL(s0 - s1)
        return outer * direction
    }

    private const val MAX8 = 256

    @JvmStatic
    fun distance8(s0: Int, s1: Int): Int {
        return distanceI(s0, s1, MAX8)
    }

    @JvmStatic
    fun compare8(s0: Int, s1: Int): Int {
        return -distance8(s0, s1)
    }

    @JvmStatic
    fun inRange8(s0: Int): Boolean {
        return (s0 >= 0) && (s0 < MAX8)
    }

    @JvmStatic
    fun increment8(s0: Int): Int {
        if (s0 < MAX8 - 1) {
            return s0 + 1
        }
        return 0
    }

    private const val MAX16 = 65536

    @JvmStatic
    fun distance16(s0: Int, s1: Int): Int {
        return distanceI(s0, s1, MAX16)
    }

    @JvmStatic
    fun compare16(s0: Int, s1: Int): Int {
        return -distance16(s0, s1)
    }

    @JvmStatic
    fun inRange16(s0: Int): Boolean {
        return (s0 >= 0) && (s0 < MAX16)
    }

    @JvmStatic
    fun increment16(s0: Int): Int {
        if (s0 < MAX16 - 1) {
            return s0 + 1
        }
        return 0
    }

    private const val MAX32 = 4294967296L

    private fun int32toULong(s0: Int): Long {
        val intermediate = s0.toLong()
        return intermediate and 0xFFFFFFFFL
    }

    @JvmStatic
    fun distance32(s0: Int, s1: Int): Int {
        return distanceL(int32toULong(s0), int32toULong(s1), MAX32).toInt()
    }

    @JvmStatic
    fun compare32(s0: Int, s1: Int): Int {
        return -distance32(s0, s1)
    }

    @JvmStatic
    fun inRange32(s0: Int): Boolean {
        return (s0 >= 0) && (s0 < MAX32)
    }

    @JvmStatic
    fun increment32(s0: Int): Int {
        if (int32toULong(s0) < MAX32 - 1L) {
            return s0 + 1
        }
        return 0
    }
}