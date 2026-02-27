package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.Base64

@Component
class RedisChallengeStore(private val template: StringRedisTemplate) {

    fun storeChallenge(sessionId: String, challenge: ByteArray) {
        template.opsForValue().set(
            "wc:$sessionId",
            Base64.getEncoder().encodeToString(challenge),
            Duration.ofMinutes(5),
        )
    }

    fun getAndDeleteChallenge(sessionId: String): ByteArray {
        val encoded = template.opsForValue().getAndDelete("wc:$sessionId")
            ?: throw BadRequestException("WebAuthn challenge expired or not found", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
        return Base64.getDecoder().decode(encoded)
    }
}
