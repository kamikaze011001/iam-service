package com.aibles.iam.authorization.domain.token

import java.time.Duration
import java.util.UUID

interface TokenStore {
    fun storeRefreshToken(token: String, userId: UUID, ttl: Duration)
    fun validateAndConsume(token: String): UUID  // atomic get+delete; throws UnauthorizedException(TOKEN_INVALID) if missing/expired
    fun revokeAllForUser(userId: UUID)
}
