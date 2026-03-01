package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component

@Component
class LoginWithGoogleUseCase(
    private val userRepository: UserRepository,
    private val createUserUseCase: CreateUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
) {
    data class Command(val oidcUser: OidcUser)
    data class Result(val user: User, val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val oidcUser = command.oidcUser
        val googleSub = oidcUser.subject
        val email = oidcUser.email ?: error("Google OIDC user missing email")
        val name = oidcUser.fullName

        val user = userRepository.findByGoogleSub(googleSub)
            ?: userRepository.findByEmail(email)
            ?: createUserUseCase.execute(CreateUserUseCase.Command(email, name, googleSub)).user

        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        user.recordLogin()
        userRepository.save(user)

        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(user, tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
