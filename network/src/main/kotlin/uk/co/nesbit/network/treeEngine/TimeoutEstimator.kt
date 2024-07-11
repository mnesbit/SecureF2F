package uk.co.nesbit.network.treeEngine

import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.math.max

class TimeoutEstimator(initialRTT: Long = START_RTT) {
    companion object {
        const val SRTT_SHIFT = 3
        const val RTTVAR_SHIFT = 2
        const val START_RTT = 2000L
        const val REQUEST_TIMEOUT_INCREMENT_MS = 200L
        const val RTT_GRANULARITY = 15L shl RTTVAR_SHIFT
    }

    private var initialized: Boolean = false
    private var rttScaled: Long = initialRTT shl SRTT_SHIFT // 8 * SRTT
    private var rttVarScaled: Long = 0L // 4 * RTTVAR

    fun rttTimeout(): Long {
        return (rttScaled shr SRTT_SHIFT) + max(rttVarScaled, RTT_GRANULARITY) // SRTT + 4 * RTTVAR downscaled by 8
    }

    fun updateRtt(sentTime: Instant, receiveTime: Instant) {
        updateRtt(ChronoUnit.MILLIS.between(sentTime, receiveTime))
    }

    fun updateRtt(replyTime: Long) {
        // Van Jacobson Algorithm for RTT
        if (!initialized) {
            initialized = true
            rttScaled = replyTime shl SRTT_SHIFT // SRTT = R in * 8 scale
            rttVarScaled = replyTime shl (RTTVAR_SHIFT - 1) // RTTVAR = R / 2 in * 4 scale
        } else {
            var replyTimeError = replyTime - (rttScaled shr SRTT_SHIFT) // (R' - SRTT) in * 1 scale
            rttScaled += replyTimeError // (7 / 8) * SRTT - (R' / 8) in * 8 scale
            if (replyTimeError < 0) {
                replyTimeError = -replyTimeError // absolute deviation
            }
            replyTimeError -= (rttVarScaled shr RTTVAR_SHIFT) // MDEV - RTTVAR / 4 in * 1 scale
            rttVarScaled += replyTimeError // (3 / 4) * RTTVAR + MDEV / 4 in * 4 scale
        }
    }

    fun updateLostPacket(incrementMS: Long = REQUEST_TIMEOUT_INCREMENT_MS) {
        if (initialized) {
            rttVarScaled += incrementMS shl RTTVAR_SHIFT
        }
    }
}