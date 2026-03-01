package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component

@Component
class LoginWithGoogleUseCase(
    private val syncGoogleUserUseCase: SyncGoogleUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
) {
    data class Command(val oidcUser: OidcUser)
    data class Result(val user: User, val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val user = syncGoogleUserUseCase.execute(SyncGoogleUserUseCase.Command(command.oidcUser)).user
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(user, tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
