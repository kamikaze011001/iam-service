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
        val userId = UUID.randomUUID()
        every { tokenStore.validateAndConsume("good-token") } returns userId
        every { tokenStore.revokeAllForUser(userId) } returns Unit

        useCase.execute(RevokeTokenUseCase.Command("good-token"))

        verify(exactly = 1) { tokenStore.validateAndConsume("good-token") }
        verify(exactly = 1) { tokenStore.revokeAllForUser(userId) }
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

    @Test
    fun `logout revokes all sessions for the user`() {
        val userId = UUID.randomUUID()
        every { tokenStore.validateAndConsume("token-1") } returns userId
        every { tokenStore.revokeAllForUser(userId) } returns Unit

        useCase.execute(RevokeTokenUseCase.Command("token-1"))

        verify(exactly = 1) { tokenStore.revokeAllForUser(userId) }
    }
}
