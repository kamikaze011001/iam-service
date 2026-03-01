package com.aibles.iam.identity.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.context.ApplicationEventPublisher
import org.springframework.stereotype.Component

@Component
class CreateUserUseCase(
    private val userRepository: UserRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {

    data class Command(val email: String, val displayName: String?, val googleSub: String?)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        if (userRepository.existsByEmail(command.email.lowercase().trim()))
            throw ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)
        val user = User.create(command.email, command.displayName, command.googleSub)
        val saved = userRepository.save(user)
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.USER_CREATED,
            userId = saved.id,
            actorId = saved.id,
            metadata = mapOf("email" to saved.email),
        ))
        return Result(saved)
    }
}
