package com.aibles.iam.authorization.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.UnauthorizedException
import com.aibles.iam.shared.web.HttpContextExtractor
import org.springframework.context.ApplicationEventPublisher
import org.springframework.stereotype.Component

@Component
class RevokeTokenUseCase(
    private val tokenStore: TokenStore,
    private val eventPublisher: ApplicationEventPublisher,
    private val httpContextExtractor: HttpContextExtractor,
) {
    data class Command(val refreshToken: String)

    fun execute(command: Command) {
        try {
            val userId = tokenStore.validateAndConsume(command.refreshToken)
            tokenStore.revokeAllForUser(userId)   // revoke all remaining sessions for this user
            eventPublisher.publishEvent(AuditDomainEvent(
                eventType = AuditEvent.TOKEN_REVOKED,
                userId = userId,
                actorId = userId,
                ipAddress = httpContextExtractor.clientIp(),
                userAgent = httpContextExtractor.userAgent(),
            ))
        } catch (e: UnauthorizedException) {
            // already revoked/expired — logout is idempotent
        }
    }
}
