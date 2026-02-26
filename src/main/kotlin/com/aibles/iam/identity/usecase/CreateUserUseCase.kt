package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class CreateUserUseCase(private val userRepository: UserRepository) {

    data class Command(val email: String, val displayName: String?, val googleSub: String?)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        if (userRepository.existsByEmail(command.email.lowercase().trim()))
            throw ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)
        val user = User.create(command.email, command.displayName, command.googleSub)
        return Result(userRepository.save(user))
    }
}
