package com.aibles.iam.audit.domain.log

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class AuditLogTest {

    @Test
    fun `create sets all fields`() {
        val userId = UUID.randomUUID()
        val actorId = UUID.randomUUID()

        val log = AuditLog.create(
            eventType = AuditEvent.USER_CREATED,
            userId = userId,
            actorId = actorId,
            ipAddress = "192.168.1.1",
            userAgent = "Mozilla/5.0",
            metadata = """{"email":"a@b.com"}""",
        )

        assertThat(log.id).isNotNull()
        assertThat(log.eventType).isEqualTo(AuditEvent.USER_CREATED)
        assertThat(log.userId).isEqualTo(userId)
        assertThat(log.actorId).isEqualTo(actorId)
        assertThat(log.ipAddress).isEqualTo("192.168.1.1")
        assertThat(log.userAgent).isEqualTo("Mozilla/5.0")
        assertThat(log.metadata).isEqualTo("""{"email":"a@b.com"}""")
        assertThat(log.createdAt).isNotNull()
    }

    @Test
    fun `create with minimal fields`() {
        val log = AuditLog.create(eventType = AuditEvent.TOKEN_ISSUED)

        assertThat(log.eventType).isEqualTo(AuditEvent.TOKEN_ISSUED)
        assertThat(log.userId).isNull()
        assertThat(log.actorId).isNull()
        assertThat(log.ipAddress).isNull()
        assertThat(log.userAgent).isNull()
        assertThat(log.metadata).isNull()
    }
}
