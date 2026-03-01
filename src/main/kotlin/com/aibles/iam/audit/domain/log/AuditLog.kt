package com.aibles.iam.audit.domain.log

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "audit_logs")
class AuditLog private constructor(
    @Id
    val id: UUID = UUID.randomUUID(),

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false)
    val eventType: AuditEvent,

    @Column(name = "user_id")
    val userId: UUID?,

    @Column(name = "actor_id")
    val actorId: UUID?,

    @Column(name = "ip_address", columnDefinition = "inet")
    val ipAddress: String?,

    @Column(name = "user_agent")
    val userAgent: String?,

    @Column(name = "metadata", columnDefinition = "jsonb")
    val metadata: String?,

    @Column(name = "created_at", nullable = false)
    val createdAt: Instant = Instant.now(),
) {
    protected constructor() : this(
        eventType = AuditEvent.USER_CREATED,
        userId = null,
        actorId = null,
        ipAddress = null,
        userAgent = null,
        metadata = null,
    )

    companion object {
        fun create(
            eventType: AuditEvent,
            userId: UUID? = null,
            actorId: UUID? = null,
            ipAddress: String? = null,
            userAgent: String? = null,
            metadata: String? = null,
        ) = AuditLog(
            eventType = eventType,
            userId = userId,
            actorId = actorId,
            ipAddress = ipAddress,
            userAgent = userAgent,
            metadata = metadata,
        )
    }
}
