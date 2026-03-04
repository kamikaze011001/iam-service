package com.aibles.iam.authentication.infra

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration

@Component
class RedisOtpStore(private val template: StringRedisTemplate) {

    companion object {
        private val OTP_TTL   = Duration.ofMinutes(5)
        private val TOKEN_TTL = Duration.ofMinutes(10)
        private val SEND_TTL  = Duration.ofMinutes(10)
        const val MAX_ATTEMPTS   = 3L
        const val MAX_SEND_COUNT = 3L
    }

    fun saveOtp(scope: OtpScope, key: String, code: String) {
        template.opsForValue().set("${scope.prefix}$key", code, OTP_TTL)
        template.delete("${scope.prefix}attempts:$key")
    }

    fun getOtp(scope: OtpScope, key: String): String? =
        template.opsForValue().get("${scope.prefix}$key")

    fun deleteOtp(scope: OtpScope, key: String) {
        template.delete(listOf("${scope.prefix}$key", "${scope.prefix}attempts:$key"))
    }

    fun incrementAttempts(scope: OtpScope, key: String): Long {
        val redisKey = "${scope.prefix}attempts:$key"
        val count = template.opsForValue().increment(redisKey) ?: 1L
        if (count == 1L) template.expire(redisKey, OTP_TTL)
        return count
    }

    val maxAttempts: Long get() = MAX_ATTEMPTS

    val maxSendCount: Long get() = MAX_SEND_COUNT

    fun incrementSendCount(scope: OtpScope, key: String): Long {
        val redisKey = "${scope.prefix}sends:$key"
        val count = template.opsForValue().increment(redisKey) ?: 1L
        if (count == 1L) template.expire(redisKey, SEND_TTL)
        return count
    }

    fun saveOtpToken(scope: OtpScope, token: String, value: String) {
        template.opsForValue().set("${scope.prefix}ok:$token", value, TOKEN_TTL)
    }

    fun consumeOtpToken(scope: OtpScope, token: String): String? =
        template.opsForValue().getAndDelete("${scope.prefix}ok:$token")
}
