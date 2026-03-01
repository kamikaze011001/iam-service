package com.aibles.iam.authorization.infra

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.UUID

@Component
class RedisTokenStore(private val template: StringRedisTemplate) : TokenStore {

    override fun storeRefreshToken(token: String, userId: UUID, ttl: Duration) {
        template.opsForValue().set("rt:$token", userId.toString(), ttl)
        template.opsForSet().add("rt:u:$userId", token)
        template.expire("rt:u:$userId", ttl)
    }

    override fun validateAndConsume(token: String): UUID {
        val userId = template.opsForValue().getAndDelete("rt:$token")
            ?: throw UnauthorizedException("Refresh token invalid or expired", ErrorCode.TOKEN_INVALID)
        val userUUID = UUID.fromString(userId)
        template.opsForSet().remove("rt:u:$userUUID", token)
        return userUUID
    }

    override fun revokeAllForUser(userId: UUID) {
        val tokens = template.opsForSet().members("rt:u:$userId") ?: emptySet()
        tokens.forEach { token -> template.delete("rt:$token") }
        template.delete("rt:u:$userId")
    }
}
