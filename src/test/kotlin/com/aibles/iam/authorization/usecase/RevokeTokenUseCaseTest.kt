package com.aibles.iam.authorization.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.context.ApplicationEventPublisher
import java.util.UUID

class RevokeTokenUseCaseTest {

    private val tokenStore = mockk<TokenStore>()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val useCase = RevokeTokenUseCase(tokenStore, eventPublisher)

    @Test
    fun `valid token is consumed from store`() {
        every { tokenStore.validateAndConsume("good-token") } returns UUID.randomUUID()

        useCase.execute(RevokeTokenUseCase.Command("good-token"))

        verify(exactly = 1) { tokenStore.validateAndConsume("good-token") }
        verify(exactly = 1) { eventPublisher.publishEvent(match<AuditDomainEvent> {
            it.eventType == AuditEvent.TOKEN_REVOKED
        }) }
    }

    @Test
    fun `already-revoked token does not throw (idempotent logout)`() {
        every { tokenStore.validateAndConsume("gone-token") } throws
            UnauthorizedException("expired", ErrorCode.TOKEN_INVALID)

        // should NOT throw — logout is idempotent
        useCase.execute(RevokeTokenUseCase.Command("gone-token"))
    }
}
