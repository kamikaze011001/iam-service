package com.aibles.iam.identity.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.web.HttpContextExtractor
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.context.ApplicationEventPublisher
import java.util.Optional
import java.util.UUID

class UpdateUserRolesUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val httpContextExtractor = mockk<HttpContextExtractor> {
        every { clientIp() } returns "127.0.0.1"
        every { userAgent() } returns "test-agent"
    }
    private val useCase = UpdateUserRolesUseCase(userRepository, eventPublisher, httpContextExtractor)

    private val actorId = UUID.randomUUID()
    private val targetUser = User.create("target@example.com")

    @Test
    fun `replaces roles and returns updated user`() {
        every { userRepository.findById(targetUser.id) } returns Optional.of(targetUser)
        every { userRepository.save(targetUser) } returns targetUser

        val result = useCase.execute(
            UpdateUserRolesUseCase.Command(actorId, targetUser.id, setOf("USER", "ADMIN"))
        )

        assertThat(result.user.roles).containsExactlyInAnyOrder("USER", "ADMIN")
        verify { userRepository.save(targetUser) }
        verify {
            eventPublisher.publishEvent(
                match<AuditDomainEvent> {
                    it.eventType == AuditEvent.USER_ROLES_UPDATED &&
                    it.userId == targetUser.id &&
                    it.actorId == actorId
                }
            )
        }
    }

    @Test
    fun `throws INVALID_ROLE for unknown role value`() {
        val ex = assertThrows<BadRequestException> {
            useCase.execute(
                UpdateUserRolesUseCase.Command(actorId, targetUser.id, setOf("USER", "SUPERUSER"))
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.INVALID_ROLE)
    }

    @Test
    fun `throws INVALID_ROLE for empty roles set`() {
        val ex = assertThrows<BadRequestException> {
            useCase.execute(
                UpdateUserRolesUseCase.Command(actorId, targetUser.id, emptySet())
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.INVALID_ROLE)
    }

    @Test
    fun `throws USER_NOT_FOUND when user does not exist`() {
        val missingId = UUID.randomUUID()
        every { userRepository.findById(missingId) } returns Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(
                UpdateUserRolesUseCase.Command(actorId, missingId, setOf("ADMIN"))
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
