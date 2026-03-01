package com.aibles.iam.identity.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.context.ApplicationEventPublisher
import java.util.Optional
import java.util.UUID

class DeleteUserUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val useCase = DeleteUserUseCase(repo, eventPublisher)

    @Test
    fun `deletes existing user`() {
        val user = User.create("a@b.com")
        every { repo.findById(user.id) } returns Optional.of(user)
        justRun { repo.delete(user) }

        useCase.execute(DeleteUserUseCase.Command(user.id))

        verify(exactly = 1) { repo.delete(user) }
        verify(exactly = 1) { eventPublisher.publishEvent(match<AuditDomainEvent> {
            it.eventType == AuditEvent.USER_DELETED
        }) }
    }

    @Test
    fun `throws NotFoundException when user not found`() {
        val id = UUID.randomUUID()
        every { repo.findById(id) } returns Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(DeleteUserUseCase.Command(id))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
