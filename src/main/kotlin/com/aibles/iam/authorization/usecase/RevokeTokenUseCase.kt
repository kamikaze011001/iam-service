package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.stereotype.Component

@Component
class RevokeTokenUseCase(private val tokenStore: TokenStore) {
    data class Command(val refreshToken: String)

    fun execute(command: Command) {
        try {
            tokenStore.validateAndConsume(command.refreshToken)
        } catch (e: UnauthorizedException) {
            // already revoked/expired — logout is idempotent
        }
    }
}
