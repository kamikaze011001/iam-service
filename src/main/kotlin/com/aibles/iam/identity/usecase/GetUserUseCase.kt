package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class GetUserUseCase(private val userRepository: UserRepository) {

    data class Query(val id: UUID)

    fun execute(query: Query): User =
        userRepository.findById(query.id)
            .orElseThrow { NotFoundException("User not found: ${query.id}", ErrorCode.USER_NOT_FOUND) }
}
