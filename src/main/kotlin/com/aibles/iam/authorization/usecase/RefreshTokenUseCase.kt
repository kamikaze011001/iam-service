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

    fun execute(command: Command): IssueTokenUseCase.Result {
        val userId = tokenStore.validateAndConsume(command.refreshToken)
        val user = getUserUseCase.execute(GetUserUseCase.Query(userId))
        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)
        return issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
    }
}
