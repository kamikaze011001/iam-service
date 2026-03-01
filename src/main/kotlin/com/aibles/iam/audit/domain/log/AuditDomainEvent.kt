package com.aibles.iam.audit.domain.log

import java.util.UUID

data class AuditDomainEvent(
    val eventType: AuditEvent,
    val userId: UUID? = null,
    val actorId: UUID? = null,
    val ipAddress: String? = null,
    val userAgent: String? = null,
    val metadata: Map<String, Any?>? = null,
)
