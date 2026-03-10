package com.aibles.iam.identity.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.web.HttpContextExtractor
import org.springframework.context.ApplicationEventPublisher
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class UpdateUserRolesUseCase(
    private val userRepository: UserRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val httpContextExtractor: HttpContextExtractor,
) {
    companion object {
        private val VALID_ROLES = setOf("USER", "ADMIN")
    }

    data class Command(val actorId: UUID, val targetUserId: UUID, val roles: Set<String>)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        if (command.roles.isEmpty()) {
            throw BadRequestException("Roles cannot be empty", ErrorCode.INVALID_ROLE)
        }
        val invalidRoles = command.roles.filterNot { it in VALID_ROLES }
        if (invalidRoles.isNotEmpty()) {
            throw BadRequestException("Invalid roles: $invalidRoles", ErrorCode.INVALID_ROLE)
        }
        val user = userRepository.findById(command.targetUserId)
            .orElseThrow { NotFoundException("User not found", ErrorCode.USER_NOT_FOUND) }
        user.updateRoles(command.roles)
        val saved = userRepository.save(user)
        eventPublisher.publishEvent(
            AuditDomainEvent(
                eventType = AuditEvent.USER_ROLES_UPDATED,
                userId = command.targetUserId,
                actorId = command.actorId,
                ipAddress = httpContextExtractor.clientIp(),
                userAgent = httpContextExtractor.userAgent(),
                metadata = mapOf("roles" to command.roles.sorted().joinToString(",")),
            )
        )
        return Result(saved)
    }
}
