package com.aibles.iam.audit.api.dto

import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import java.time.Instant
import java.util.UUID

data class AuditLogResponse(
    val id: UUID,
    val eventType: AuditEvent,
    val userId: UUID?,
    val actorId: UUID?,
    val ipAddress: String?,
    val userAgent: String?,
    val metadata: String?,
    val createdAt: Instant,
) {
    companion object {
        fun from(item: QueryAuditLogsUseCase.AuditLogItem) = AuditLogResponse(
            id = item.id,
            eventType = item.eventType,
            userId = item.userId,
            actorId = item.actorId,
            ipAddress = item.ipAddress,
            userAgent = item.userAgent,
            metadata = item.metadata,
            createdAt = item.createdAt,
        )
    }
}
