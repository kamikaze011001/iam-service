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

    companion object {
        private const val TOKEN_PREFIX = "rt:"
        private const val USER_SET_PREFIX = "rt:u:"
    }

    override fun storeRefreshToken(token: String, userId: UUID, ttl: Duration) {
        template.opsForValue().set("$TOKEN_PREFIX$token", userId.toString(), ttl)
        template.opsForSet().add("$USER_SET_PREFIX$userId", token)
        template.expire("$USER_SET_PREFIX$userId", ttl)
    }

    override fun validateAndConsume(token: String): UUID {
        val userId = template.opsForValue().getAndDelete("$TOKEN_PREFIX$token")
            ?: throw UnauthorizedException("Refresh token invalid or expired", ErrorCode.TOKEN_INVALID)
        val userUUID = UUID.fromString(userId)
        template.opsForSet().remove("$USER_SET_PREFIX$userUUID", token)
        return userUUID
    }

    override fun revokeAllForUser(userId: UUID) {
        val tokens = template.opsForSet().members("$USER_SET_PREFIX$userId") ?: emptySet()
        val keys = tokens.map { "$TOKEN_PREFIX$it" } + "$USER_SET_PREFIX$userId"
        template.delete(keys)
    }
}
