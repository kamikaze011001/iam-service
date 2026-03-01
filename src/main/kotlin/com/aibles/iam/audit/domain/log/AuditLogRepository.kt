package com.aibles.iam.audit.domain.log

import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import java.time.Instant
import java.util.UUID

interface AuditLogRepository : JpaRepository<AuditLog, UUID> {

    @Query(
        """
        SELECT a FROM AuditLog a
        WHERE (:eventType IS NULL OR a.eventType = :eventType)
          AND (:userId IS NULL OR a.userId = :userId)
          AND (:from IS NULL OR a.createdAt >= :from)
          AND (:to IS NULL OR a.createdAt <= :to)
        ORDER BY a.createdAt DESC
        """,
    )
    fun findFiltered(
        eventType: AuditEvent?,
        userId: UUID?,
        from: Instant?,
        to: Instant?,
        pageable: Pageable,
    ): Page<AuditLog>
}
