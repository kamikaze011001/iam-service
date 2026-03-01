package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.domain.log.AuditLog
import com.aibles.iam.audit.domain.log.AuditLogRepository
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.data.domain.PageImpl
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.domain.Specification
import java.time.Instant
import java.util.UUID

class QueryAuditLogsUseCaseTest {

    private val repo = mockk<AuditLogRepository>()
    private val useCase = QueryAuditLogsUseCase(repo)

    @Test
    fun `execute returns paginated audit logs`() {
        val log = AuditLog.create(eventType = AuditEvent.USER_CREATED, userId = UUID.randomUUID())
        val page = PageImpl(listOf(log))

        every {
            repo.findAll(any<Specification<AuditLog>>(), any<Pageable>())
        } returns page

        val result = useCase.execute(
            QueryAuditLogsUseCase.Query(page = 0, size = 20)
        )

        assertThat(result.content).hasSize(1)
        assertThat(result.totalElements).isEqualTo(1)
        assertThat(result.content[0].eventType).isEqualTo(AuditEvent.USER_CREATED)
    }

    @Test
    fun `execute passes filters to repository`() {
        val userId = UUID.randomUUID()
        val from = Instant.parse("2026-01-01T00:00:00Z")
        val to = Instant.parse("2026-12-31T23:59:59Z")
        val page = PageImpl(emptyList<AuditLog>())

        every {
            repo.findAll(any<Specification<AuditLog>>(), any<Pageable>())
        } returns page

        val result = useCase.execute(
            QueryAuditLogsUseCase.Query(
                eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
                userId = userId,
                from = from,
                to = to,
                page = 0,
                size = 10,
            )
        )

        assertThat(result.content).isEmpty()
        assertThat(result.totalElements).isEqualTo(0)
    }
}
