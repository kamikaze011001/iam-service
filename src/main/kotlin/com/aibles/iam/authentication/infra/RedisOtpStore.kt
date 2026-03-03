package com.aibles.iam.authentication.infra

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.UUID

@Component
class RedisOtpStore(private val template: StringRedisTemplate) {

    companion object {
        private const val OTP_PREFIX      = "otp:reg:"
        private const val ATTEMPTS_PREFIX = "otp:reg:attempts:"
        private const val TOKEN_PREFIX    = "otp:reg:ok:"
        private val OTP_TTL   = Duration.ofMinutes(5)
        private val TOKEN_TTL = Duration.ofMinutes(10)
        const val MAX_ATTEMPTS = 3L
    }

    fun saveOtp(userId: UUID, code: String) {
        template.opsForValue().set("$OTP_PREFIX$userId", code, OTP_TTL)
        template.delete("$ATTEMPTS_PREFIX$userId")   // reset attempts on resend
    }

    fun getOtp(userId: UUID): String? =
        template.opsForValue().get("$OTP_PREFIX$userId")

    fun deleteOtp(userId: UUID) {
        template.delete("$OTP_PREFIX$userId")
        template.delete("$ATTEMPTS_PREFIX$userId")
    }

    /** Increments and returns the new attempt count. */
    fun incrementAttempts(userId: UUID): Long {
        val key = "$ATTEMPTS_PREFIX$userId"
        val count = template.opsForValue().increment(key) ?: 1L
        if (count == 1L) template.expire(key, OTP_TTL)   // set TTL on first increment
        return count
    }

    val maxAttempts: Long get() = MAX_ATTEMPTS

    fun saveOtpToken(token: String, userId: UUID) {
        template.opsForValue().set("$TOKEN_PREFIX$token", userId.toString(), TOKEN_TTL)
    }

    /** Returns the userId the token was issued for, or null if expired/not found. Deletes on read (one-time). */
    fun consumeOtpToken(token: String): UUID? =
        template.opsForValue().getAndDelete("$TOKEN_PREFIX$token")?.let { UUID.fromString(it) }
}
