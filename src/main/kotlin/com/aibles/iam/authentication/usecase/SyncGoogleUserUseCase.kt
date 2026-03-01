package com.aibles.iam.authentication.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component

@Component
class SyncGoogleUserUseCase(
    private val userRepository: UserRepository,
    private val createUserUseCase: CreateUserUseCase,
) {
    data class Command(val oidcUser: OidcUser)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        val googleSub = command.oidcUser.subject
        val email = command.oidcUser.email ?: error("Google OIDC user missing email")
        val name = command.oidcUser.fullName

        val user = userRepository.findByGoogleSub(googleSub)
            ?: userRepository.findByEmail(email)?.also { it.linkGoogleAccount(googleSub) }
            ?: createUserUseCase.execute(CreateUserUseCase.Command(email, name, googleSub)).user

        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        user.recordLogin()
        userRepository.save(user)
        return Result(user)
    }
}
