package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import org.springframework.stereotype.Component

@Component
class RefreshTokenUseCase(
    private val tokenStore: TokenStore,
    private val getUserUseCase: GetUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
) {
    data class Command(val refreshToken: String)
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val userId = tokenStore.validateAndConsume(command.refreshToken)
        val user = getUserUseCase.execute(GetUserUseCase.Query(userId))
        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
