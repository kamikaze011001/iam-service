package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.domain.log.AuditLog
import com.aibles.iam.audit.domain.log.AuditLogRepository
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import java.util.UUID

class RecordAuditEventUseCaseTest {

    private val repo = mockk<AuditLogRepository>()
    private val objectMapper = jacksonObjectMapper()
    private val useCase = RecordAuditEventUseCase(repo, objectMapper)

    @Test
    fun `onAuditEvent persists audit log with all fields`() {
        val captured = slot<AuditLog>()
        every { repo.save(capture(captured)) } answers { firstArg() }

        val userId = UUID.randomUUID()
        val actorId = UUID.randomUUID()
        val event = AuditDomainEvent(
            eventType = AuditEvent.USER_CREATED,
            userId = userId,
            actorId = actorId,
            ipAddress = "10.0.0.1",
            userAgent = "TestAgent",
            metadata = mapOf("email" to "a@b.com"),
        )

        useCase.onAuditEvent(event)

        verify(exactly = 1) { repo.save(any()) }
        assertThat(captured.captured.eventType).isEqualTo(AuditEvent.USER_CREATED)
        assertThat(captured.captured.userId).isEqualTo(userId)
        assertThat(captured.captured.actorId).isEqualTo(actorId)
        assertThat(captured.captured.ipAddress).isEqualTo("10.0.0.1")
        assertThat(captured.captured.userAgent).isEqualTo("TestAgent")
        assertThat(captured.captured.metadata).contains("\"email\"")
    }

    @Test
    fun `onAuditEvent persists with null metadata when not provided`() {
        every { repo.save(any()) } answers { firstArg() }

        val event = AuditDomainEvent(
            eventType = AuditEvent.TOKEN_ISSUED,
        )

        useCase.onAuditEvent(event)

        verify(exactly = 1) { repo.save(match { it.metadata == null }) }
    }

    @Test
    fun `onAuditEvent swallows exception when save fails`() {
        every { repo.save(any()) } throws RuntimeException("DB down")

        val event = AuditDomainEvent(eventType = AuditEvent.USER_CREATED)

        assertDoesNotThrow { useCase.onAuditEvent(event) }
    }
}
