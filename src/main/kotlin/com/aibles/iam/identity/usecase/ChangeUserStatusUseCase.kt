package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.domain.user.UserStatus
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class ChangeUserStatusUseCase(private val userRepository: UserRepository) {

    data class Command(val id: UUID, val status: UserStatus)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        val user = userRepository.findById(command.id)
            .orElseThrow { NotFoundException("User not found: ${command.id}", ErrorCode.USER_NOT_FOUND) }
        when (command.status) {
            UserStatus.ACTIVE -> user.enable()
            UserStatus.DISABLED -> user.disable()
        }
        return Result(userRepository.save(user))
    }
}
