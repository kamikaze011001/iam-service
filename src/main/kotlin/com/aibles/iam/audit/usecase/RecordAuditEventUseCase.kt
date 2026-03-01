package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditLog
import com.aibles.iam.audit.domain.log.AuditLogRepository
import com.fasterxml.jackson.databind.ObjectMapper
import org.slf4j.LoggerFactory
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

@Component
class RecordAuditEventUseCase(
    private val auditLogRepository: AuditLogRepository,
    private val objectMapper: ObjectMapper,
) {

    private val logger = LoggerFactory.getLogger(RecordAuditEventUseCase::class.java)

    @EventListener
    fun onAuditEvent(event: AuditDomainEvent) {
        try {
            val log = AuditLog.create(
                eventType = event.eventType,
                userId = event.userId,
                actorId = event.actorId,
                ipAddress = event.ipAddress,
                userAgent = event.userAgent,
                metadata = event.metadata?.let { objectMapper.writeValueAsString(it) },
            )
            auditLogRepository.save(log)
        } catch (e: Exception) {
            logger.error("Failed to record audit event: {} for user {}", event.eventType, event.userId, e)
        }
    }
}
