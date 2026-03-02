# Sprint 6 — Audit Logs BC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the Audit Logs bounded context — append-only event recording via Spring `ApplicationEventPublisher` + a paginated query API for admin access.

**Architecture:** Other BCs publish domain events (`AuditDomainEvent`) via Spring's `ApplicationEventPublisher`. The audit BC listens with `@EventListener` in `RecordAuditEventUseCase`, persists `AuditLog` entities to the existing `audit_logs` table. `QueryAuditLogsUseCase` supports paginated queries with optional filters (event type, user ID, date range). `AuditLogsController` exposes the query API at `/api/v1/audit-logs`.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Spring Data JPA, Spring `ApplicationEventPublisher` / `@EventListener`, MockK, `@WebMvcTest`

---

## Task 1: AuditLog aggregate + AuditEvent enum + repository

**GitHub Issue Title:** `feat(audit): AuditLog entity, AuditEvent enum, and repository`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt`
- Create: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt`
- Create: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogRepository.kt`
- Test: `src/test/kotlin/com/aibles/iam/audit/domain/log/AuditLogTest.kt`

### Step 1: Write the AuditEvent enum

```kotlin
// src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt
package com.aibles.iam.audit.domain.log

enum class AuditEvent {
    // Identity
    USER_CREATED,
    USER_UPDATED,
    USER_STATUS_CHANGED,
    USER_DELETED,

    // Authentication
    LOGIN_GOOGLE_SUCCESS,
    LOGIN_GOOGLE_FAILURE,
    PASSKEY_REGISTERED,
    PASSKEY_AUTHENTICATED,
    PASSKEY_DELETED,

    // Authorization
    TOKEN_ISSUED,
    TOKEN_REFRESHED,
    TOKEN_REVOKED,

    // OAuth2 AS
    OAUTH2_AUTHORIZATION_GRANTED,
}
```

### Step 2: Write the AuditLog entity

Maps to the existing `audit_logs` table from V1 migration. Append-only — no update methods.

```kotlin
// src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt
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
```

**Note on `metadata` mapping:** The DB column is `JSONB`, but we store it as a plain `String` in the entity (serialized JSON). This avoids adding a Hibernate `jsonb` type dependency. The use case is responsible for serializing metadata to JSON before calling `AuditLog.create()`.

### Step 3: Write the AuditLogRepository

```kotlin
// src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogRepository.kt
package com.aibles.iam.audit.domain.log

import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import java.time.Instant
import java.util.UUID

interface AuditLogRepository : JpaRepository<AuditLog, UUID> {

    @Query("""
        SELECT a FROM AuditLog a
        WHERE (:eventType IS NULL OR a.eventType = :eventType)
          AND (:userId IS NULL OR a.userId = :userId)
          AND (:from IS NULL OR a.createdAt >= :from)
          AND (:to IS NULL OR a.createdAt <= :to)
        ORDER BY a.createdAt DESC
    """)
    fun findFiltered(
        eventType: AuditEvent?,
        userId: UUID?,
        from: Instant?,
        to: Instant?,
        pageable: Pageable,
    ): Page<AuditLog>
}
```

### Step 4: Write the failing test for AuditLog.create

```kotlin
// src/test/kotlin/com/aibles/iam/audit/domain/log/AuditLogTest.kt
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
```

### Step 5: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 6: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/ src/test/kotlin/com/aibles/iam/audit/
git commit -m "feat(audit): AuditLog entity, AuditEvent enum, and repository"
```

---

## Task 2: RecordAuditEventUseCase + AuditDomainEvent

**GitHub Issue Title:** `feat(audit): RecordAuditEventUseCase with Spring event listener`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditDomainEvent.kt`
- Create: `src/main/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCase.kt`
- Test: `src/test/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCaseTest.kt`

### Step 1: Write the AuditDomainEvent

This is the event published by other BCs via `ApplicationEventPublisher`. It's a simple data class — not a Spring `ApplicationEvent` subclass. Spring supports publishing any object since 4.2.

```kotlin
// src/main/kotlin/com/aibles/iam/audit/domain/log/AuditDomainEvent.kt
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
```

### Step 2: Write the failing test

```kotlin
// src/test/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCaseTest.kt
package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.domain.log.AuditLog
import com.aibles.iam.audit.domain.log.AuditLogRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class RecordAuditEventUseCaseTest {

    private val repo = mockk<AuditLogRepository>()
    private val useCase = RecordAuditEventUseCase(repo)

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
}
```

### Step 3: Write the RecordAuditEventUseCase

```kotlin
// src/main/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCase.kt
package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditLog
import com.aibles.iam.audit.domain.log.AuditLogRepository
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

@Component
class RecordAuditEventUseCase(private val auditLogRepository: AuditLogRepository) {

    private val objectMapper = jacksonObjectMapper()

    @EventListener
    fun onAuditEvent(event: AuditDomainEvent) {
        val log = AuditLog.create(
            eventType = event.eventType,
            userId = event.userId,
            actorId = event.actorId,
            ipAddress = event.ipAddress,
            userAgent = event.userAgent,
            metadata = event.metadata?.let { objectMapper.writeValueAsString(it) },
        )
        auditLogRepository.save(log)
    }
}
```

### Step 4: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 5: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/ src/test/kotlin/com/aibles/iam/audit/
git commit -m "feat(audit): RecordAuditEventUseCase with Spring event listener"
```

---

## Task 3: QueryAuditLogsUseCase

**GitHub Issue Title:** `feat(audit): QueryAuditLogsUseCase with pagination and filters`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt`
- Test: `src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt`

### Step 1: Write the failing test

```kotlin
// src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt
package com.aibles.iam.audit.usecase

import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.domain.log.AuditLog
import com.aibles.iam.audit.domain.log.AuditLogRepository
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.data.domain.PageImpl
import org.springframework.data.domain.PageRequest
import java.time.Instant
import java.util.UUID

class QueryAuditLogsUseCaseTest {

    private val repo = mockk<AuditLogRepository>()
    private val useCase = QueryAuditLogsUseCase(repo)

    @Test
    fun `execute returns paginated audit logs`() {
        val log = AuditLog.create(eventType = AuditEvent.USER_CREATED, userId = UUID.randomUUID())
        val page = PageImpl(listOf(log), PageRequest.of(0, 20), 1)

        every {
            repo.findFiltered(null, null, null, null, PageRequest.of(0, 20))
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
        val page = PageImpl(emptyList<AuditLog>(), PageRequest.of(0, 10), 0)

        every {
            repo.findFiltered(AuditEvent.LOGIN_GOOGLE_SUCCESS, userId, from, to, PageRequest.of(0, 10))
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
```

### Step 2: Write the QueryAuditLogsUseCase

```kotlin
// src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt
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
```

### Step 3: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 4: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt \
        src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt
git commit -m "feat(audit): QueryAuditLogsUseCase with pagination and filters"
```

---

## Task 4: AuditLogsController + SecurityConfig update

**GitHub Issue Title:** `feat(audit): AuditLogsController REST API with paginated query`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/audit/api/AuditLogsController.kt`
- Create: `src/main/kotlin/com/aibles/iam/audit/api/dto/AuditLogResponse.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt` — add `/api/v1/audit-logs` to authenticated endpoints (already the default — `anyRequest().authenticated()`)
- Test: `src/test/kotlin/com/aibles/iam/audit/api/AuditLogsControllerTest.kt`

### Step 1: Write the AuditLogResponse DTO

```kotlin
// src/main/kotlin/com/aibles/iam/audit/api/dto/AuditLogResponse.kt
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
```

### Step 2: Write the AuditLogsController

```kotlin
// src/main/kotlin/com/aibles/iam/audit/api/AuditLogsController.kt
package com.aibles.iam.audit.api

import com.aibles.iam.audit.api.dto.AuditLogResponse
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.shared.pagination.PageResponse
import com.aibles.iam.shared.response.ApiResponse
import org.springframework.format.annotation.DateTimeFormat
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

@RestController
@RequestMapping("/api/v1/audit-logs")
class AuditLogsController(
    private val queryAuditLogsUseCase: QueryAuditLogsUseCase,
) {

    @GetMapping
    fun getAuditLogs(
        @RequestParam(required = false) eventType: AuditEvent?,
        @RequestParam(required = false) userId: UUID?,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) from: Instant?,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) to: Instant?,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
    ): ApiResponse<PageResponse<AuditLogResponse>> {
        val result = queryAuditLogsUseCase.execute(
            QueryAuditLogsUseCase.Query(
                eventType = eventType,
                userId = userId,
                from = from,
                to = to,
                page = page,
                size = size,
            )
        )
        return ApiResponse.ok(
            PageResponse(
                content = result.content.map { AuditLogResponse.from(it) },
                page = result.page,
                size = result.size,
                totalElements = result.totalElements,
                totalPages = result.totalPages,
            )
        )
    }
}
```

### Step 3: Write the controller test

`@WebMvcTest` scans ALL controllers in the classpath, so you must `@MockkBean` every use case injected by every controller. Follow the established pattern from `UsersControllerTest`.

```kotlin
// src/test/kotlin/com/aibles/iam/audit/api/AuditLogsControllerTest.kt
package com.aibles.iam.audit.api

import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.audit.usecase.RecordAuditEventUseCase
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.identity.usecase.ChangeUserStatusUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.identity.usecase.DeleteUserUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.identity.usecase.UpdateUserUseCase
import com.aibles.iam.shared.error.GlobalExceptionHandler
import com.aibles.iam.shared.pagination.PageResponse
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.time.Instant
import java.util.UUID

@WebMvcTest
@Import(GlobalExceptionHandler::class, AuditLogsController::class)
@AutoConfigureMockMvc(addFilters = false)
class AuditLogsControllerTest {

    @Autowired lateinit var mockMvc: MockMvc
    @MockkBean lateinit var queryAuditLogsUseCase: QueryAuditLogsUseCase

    // RecordAuditEventUseCase is a @Component with @EventListener — must be mocked
    @MockkBean lateinit var recordAuditEventUseCase: RecordAuditEventUseCase

    // UsersController deps
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase

    // AuthController deps
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase

    // PasskeyController deps
    @MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
    @MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
    @MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
    @MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
    @MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase
    @MockkBean lateinit var passkeyCredentialRepository: PasskeyCredentialRepository

    @Test
    fun `GET audit-logs returns paginated response`() {
        val logId = UUID.randomUUID()
        val userId = UUID.randomUUID()
        val now = Instant.now()

        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = listOf(
                QueryAuditLogsUseCase.AuditLogItem(
                    id = logId,
                    eventType = AuditEvent.USER_CREATED,
                    userId = userId,
                    actorId = null,
                    ipAddress = "10.0.0.1",
                    userAgent = "TestAgent",
                    metadata = null,
                    createdAt = now,
                )
            ),
            page = 0,
            size = 20,
            totalElements = 1,
            totalPages = 1,
        )

        mockMvc.get("/api/v1/audit-logs")
            .andExpect {
                status { isOk() }
                jsonPath("$.success") { value(true) }
                jsonPath("$.data.content[0].eventType") { value("USER_CREATED") }
                jsonPath("$.data.content[0].ipAddress") { value("10.0.0.1") }
                jsonPath("$.data.totalElements") { value(1) }
                jsonPath("$.data.page") { value(0) }
            }
    }

    @Test
    fun `GET audit-logs with filters passes params`() {
        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = emptyList(),
            page = 0,
            size = 10,
            totalElements = 0,
            totalPages = 0,
        )

        mockMvc.get("/api/v1/audit-logs") {
            param("eventType", "LOGIN_GOOGLE_SUCCESS")
            param("page", "0")
            param("size", "10")
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.content") { isEmpty() }
        }
    }

    @Test
    fun `GET audit-logs returns empty page when no logs`() {
        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = emptyList(),
            page = 0,
            size = 20,
            totalElements = 0,
            totalPages = 0,
        )

        mockMvc.get("/api/v1/audit-logs")
            .andExpect {
                status { isOk() }
                jsonPath("$.success") { value(true) }
                jsonPath("$.data.totalElements") { value(0) }
            }
    }
}
```

### Step 4: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 5: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/api/ \
        src/test/kotlin/com/aibles/iam/audit/api/
git commit -m "feat(audit): AuditLogsController REST API with paginated query"
```

---

## Task 5: Publish audit events from existing BCs

**GitHub Issue Title:** `feat(audit): publish AuditDomainEvent from identity, authentication, and authorization BCs`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/identity/usecase/CreateUserUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/identity/usecase/UpdateUserUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/identity/usecase/ChangeUserStatusUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/identity/usecase/DeleteUserUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authorization/usecase/RefreshTokenUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt`
- Modify existing tests to verify `eventPublisher.publishEvent(...)` is called

### Pattern

Each use case that should publish audit events injects `ApplicationEventPublisher` and calls `publishEvent(AuditDomainEvent(...))` after the main operation succeeds.

**Example — CreateUserUseCase (before):**
```kotlin
@Component
class CreateUserUseCase(private val userRepository: UserRepository) {
    fun execute(command: Command): Result { ... }
}
```

**Example — CreateUserUseCase (after):**
```kotlin
@Component
class CreateUserUseCase(
    private val userRepository: UserRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {
    fun execute(command: Command): Result {
        // ... existing logic ...
        val user = userRepository.save(...)
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.USER_CREATED,
            userId = user.id,
            actorId = user.id,
            metadata = mapOf("email" to user.email),
        ))
        return Result(user)
    }
}
```

### Use cases to wire up

| Use Case / Handler | AuditEvent | userId | actorId | metadata |
|---|---|---|---|---|
| `CreateUserUseCase` | `USER_CREATED` | `user.id` | `user.id` | `email` |
| `UpdateUserUseCase` | `USER_UPDATED` | `user.id` | `user.id` | `displayName` |
| `ChangeUserStatusUseCase` | `USER_STATUS_CHANGED` | `user.id` | `user.id` | `status` |
| `DeleteUserUseCase` | `USER_DELETED` | command `id` | command `id` | — |
| `GoogleOAuth2SuccessHandler` | `LOGIN_GOOGLE_SUCCESS` | `user.id` | `user.id` | `email` |
| `RefreshTokenUseCase` | `TOKEN_REFRESHED` | `userId` | `userId` | — |
| `RevokeTokenUseCase` | `TOKEN_REVOKED` | `userId` | `userId` | — |

### Step 1: Add `eventPublisher` to `CreateUserUseCase`

Read the current file, add `ApplicationEventPublisher` as constructor param, add `publishEvent` after save.

```kotlin
import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import org.springframework.context.ApplicationEventPublisher

@Component
class CreateUserUseCase(
    private val userRepository: UserRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {
    // ... Command, Result unchanged ...

    fun execute(command: Command): Result {
        if (userRepository.existsByEmail(command.email.lowercase().trim()))
            throw ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)
        val user = User.create(command.email, command.displayName, command.googleSub)
        val saved = userRepository.save(user)
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.USER_CREATED,
            userId = saved.id,
            actorId = saved.id,
            metadata = mapOf("email" to saved.email),
        ))
        return Result(saved)
    }
}
```

### Step 2: Update `CreateUserUseCaseTest`

Add `eventPublisher` mock, verify it's called.

```kotlin
private val repo = mockk<UserRepository>()
private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
private val useCase = CreateUserUseCase(repo, eventPublisher)

// In existing "creates and saves user" test, add:
verify(exactly = 1) { eventPublisher.publishEvent(match<AuditDomainEvent> {
    it.eventType == AuditEvent.USER_CREATED && it.metadata?.get("email") == "a@b.com"
}) }
```

### Step 3: Repeat for UpdateUserUseCase, ChangeUserStatusUseCase, DeleteUserUseCase

Same pattern — inject `ApplicationEventPublisher`, publish after main operation, update test to mock publisher with `relaxed = true`.

### Step 4: Wire GoogleOAuth2SuccessHandler

The handler already creates the user. Add `ApplicationEventPublisher`, publish `LOGIN_GOOGLE_SUCCESS` after `loginWithGoogleUseCase.execute()` succeeds.

### Step 5: Wire RefreshTokenUseCase and RevokeTokenUseCase

Same pattern.

### Step 6: Run all tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 7: Commit

```bash
git add -A
git commit -m "feat(audit): publish AuditDomainEvent from identity, authentication, and authorization BCs"
```

---

## Summary

| Task | Issue | Description |
|------|-------|-------------|
| 1 | AuditLog aggregate | Entity, enum, repository — maps to existing `audit_logs` table |
| 2 | RecordAuditEventUseCase | `@EventListener` that persists `AuditDomainEvent` to DB |
| 3 | QueryAuditLogsUseCase | Paginated query with filters (event type, user ID, date range) |
| 4 | AuditLogsController | `GET /api/v1/audit-logs` — authenticated, paginated response |
| 5 | Publish events from BCs | Wire `ApplicationEventPublisher` into identity, auth, authz use cases |

**No new Flyway migration needed** — the `audit_logs` table already exists in V1.

**Security:** The `/api/v1/audit-logs` endpoint is already covered by `anyRequest().authenticated()` in `SecurityConfig`. No changes needed.
