package com.aibles.iam.identity.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import org.springframework.context.ApplicationEventPublisher
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class DeleteUserUseCase(
    private val userRepository: UserRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {

    data class Command(val id: UUID)

    fun execute(command: Command) {
        val user = userRepository.findById(command.id)
            .orElseThrow { NotFoundException("User not found: ${command.id}", ErrorCode.USER_NOT_FOUND) }
        userRepository.delete(user)
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.USER_DELETED,
            userId = command.id,
            actorId = command.id,
        ))
    }
}
