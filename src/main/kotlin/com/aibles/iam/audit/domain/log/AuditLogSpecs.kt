package com.aibles.iam.audit.domain.log

import org.springframework.data.jpa.domain.Specification
import java.time.Instant
import java.util.UUID

object AuditLogSpecs {

    fun eventTypeEquals(eventType: AuditEvent?): Specification<AuditLog>? =
        eventType?.let { Specification { root, _, cb -> cb.equal(root.get<AuditEvent>("eventType"), it) } }

    fun userIdEquals(userId: UUID?): Specification<AuditLog>? =
        userId?.let { Specification { root, _, cb -> cb.equal(root.get<UUID>("userId"), it) } }

    fun createdAfter(from: Instant?): Specification<AuditLog>? =
        from?.let { Specification { root, _, cb -> cb.greaterThanOrEqualTo(root.get("createdAt"), it) } }

    fun createdBefore(to: Instant?): Specification<AuditLog>? =
        to?.let { Specification { root, _, cb -> cb.lessThanOrEqualTo(root.get("createdAt"), it) } }

    fun filtered(
        eventType: AuditEvent?,
        userId: UUID?,
        from: Instant?,
        to: Instant?,
    ): Specification<AuditLog> {
        var spec: Specification<AuditLog> = Specification.where(null)
        eventTypeEquals(eventType)?.let { spec = spec.and(it) }
        userIdEquals(userId)?.let { spec = spec.and(it) }
        createdAfter(from)?.let { spec = spec.and(it) }
        createdBefore(to)?.let { spec = spec.and(it) }
        return spec
    }
}
