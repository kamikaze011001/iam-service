package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.domain.log.AuditLogRepository
import com.aibles.iam.shared.pagination.PageResponse
import org.springframework.data.domain.PageRequest
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.UUID

@Component
class QueryAuditLogsUseCase(private val auditLogRepository: AuditLogRepository) {

    data class Query(
        val eventType: AuditEvent? = null,
        val userId: UUID? = null,
        val from: Instant? = null,
        val to: Instant? = null,
        val page: Int = 0,
        val size: Int = 20,
    )

    data class AuditLogItem(
        val id: UUID,
        val eventType: AuditEvent,
        val userId: UUID?,
        val actorId: UUID?,
        val ipAddress: String?,
        val userAgent: String?,
        val metadata: String?,
        val createdAt: Instant,
    )

    fun execute(query: Query): PageResponse<AuditLogItem> {
        val page = auditLogRepository.findFiltered(
            eventType = query.eventType,
            userId = query.userId,
            from = query.from,
            to = query.to,
            pageable = PageRequest.of(query.page, query.size),
        )
        return PageResponse(
            content = page.content.map { log ->
                AuditLogItem(
                    id = log.id,
                    eventType = log.eventType,
                    userId = log.userId,
                    actorId = log.actorId,
                    ipAddress = log.ipAddress,
                    userAgent = log.userAgent,
                    metadata = log.metadata,
                    createdAt = log.createdAt,
                )
            },
            page = page.number,
            size = page.size,
            totalElements = page.totalElements,
            totalPages = page.totalPages,
        )
    }
}
