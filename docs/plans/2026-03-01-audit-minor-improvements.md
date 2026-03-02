# Audit Minor Improvements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Address the 4 minor/suggestion findings from the Sprint 6 final code review — `@JsonRawValue` on metadata, dual-event documentation, composite index for query performance, and `LOGIN_GOOGLE_FAILURE` audit event via failure handler.

**Architecture:** Each task is independent. Task 1 is a one-line annotation change. Task 2 adds a code comment. Task 3 is a Flyway migration. Task 4 creates a new `AuthenticationFailureHandler` that publishes `LOGIN_GOOGLE_FAILURE` and wires it into SecurityConfig.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Spring Security 6.x `AuthenticationFailureHandler`, Flyway, Jackson `@JsonRawValue`, MockK

---

## Task 1: `@JsonRawValue` on metadata in AuditLogResponse

**GitHub Issue Title:** `chore(audit): return metadata as nested JSON object in API response`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/audit/api/dto/AuditLogResponse.kt`
- Modify: `src/test/kotlin/com/aibles/iam/audit/api/AuditLogsControllerTest.kt`

### Step 1: Add `@JsonRawValue` annotation

In `AuditLogResponse.kt`, add import `com.fasterxml.jackson.annotation.JsonRawValue` and annotate the `metadata` field:

```kotlin
// Before:
    val metadata: String?,

// After:
    @JsonRawValue val metadata: String?,
```

This makes Jackson emit the raw JSON string as-is instead of escaping it. So instead of:
```json
"metadata": "{\"email\":\"a@b.com\"}"
```
The API now returns:
```json
"metadata": {"email":"a@b.com"}
```

When `metadata` is `null`, Jackson still emits `"metadata": null` — no change needed.

### Step 2: Update the controller test to verify nested JSON

In `AuditLogsControllerTest.kt`, the first test `GET audit-logs returns paginated response` currently uses `metadata = null`. Add a new test that verifies metadata is returned as a nested JSON object:

```kotlin
@Test
fun `GET audit-logs returns metadata as nested JSON object`() {
    val logId = UUID.randomUUID()
    val now = Instant.now()

    every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
        content = listOf(
            QueryAuditLogsUseCase.AuditLogItem(
                id = logId,
                eventType = AuditEvent.USER_CREATED,
                userId = null,
                actorId = null,
                ipAddress = null,
                userAgent = null,
                metadata = """{"email":"a@b.com"}""",
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
            jsonPath("$.data.content[0].metadata.email") { value("a@b.com") }
        }
}
```

The key assertion is `$.data.content[0].metadata.email` — this proves metadata is a nested object, not an escaped string (an escaped string would fail this path).

### Step 3: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 4: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/api/dto/AuditLogResponse.kt \
        src/test/kotlin/com/aibles/iam/audit/api/AuditLogsControllerTest.kt
git commit -m "chore(audit): return metadata as nested JSON object in API response"
```

---

## Task 2: Document dual audit events on first Google login

**GitHub Issue Title:** `docs(audit): document dual audit events on first-time Google login`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`

### Step 1: Add comment

In `GoogleOAuth2SuccessHandler.kt`, above the `eventPublisher.publishEvent(...)` call (line 47), add a comment explaining the dual-event behavior:

```kotlin
        // Ensure user exists in DB for both flows
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))

        // Note: For first-time users, CreateUserUseCase (called inside LoginWithGoogleUseCase)
        // also publishes USER_CREATED. So a first login produces two audit events:
        // USER_CREATED + LOGIN_GOOGLE_SUCCESS. This is intentional — they are distinct operations.
        eventPublisher.publishEvent(AuditDomainEvent(
```

### Step 2: Commit

```bash
git add src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt
git commit -m "docs(audit): document dual audit events on first-time Google login"
```

---

## Task 3: Add composite index for audit log queries

**GitHub Issue Title:** `perf(audit): add composite index for filtered audit log queries`

**Files:**
- Create: `src/main/resources/db/migration/V3__audit_composite_index.sql`

### Step 1: Create V3 migration

The existing V1 migration has 3 separate single-column indexes (`idx_audit_user_id`, `idx_audit_created`, `idx_audit_event`). For the `findFiltered` query with `ORDER BY created_at DESC`, a composite index is more efficient:

```sql
-- V3: Composite index for filtered audit log queries.
-- The QueryAuditLogsUseCase filters by event_type and/or user_id
-- and always orders by created_at DESC. This composite index
-- covers the most common query patterns efficiently.
CREATE INDEX idx_audit_filtered ON audit_logs (event_type, user_id, created_at DESC);
```

Keep the existing single-column indexes — they cover different query patterns (e.g., lookup by `user_id` alone).

### Step 2: Run tests

Run: `./gradlew test`
Expected: all tests PASS (Flyway runs migration against Testcontainers DB)

### Step 3: Commit

```bash
git add src/main/resources/db/migration/V3__audit_composite_index.sql
git commit -m "perf(audit): add composite index for filtered audit log queries"
```

---

## Task 4: Publish `LOGIN_GOOGLE_FAILURE` via AuthenticationFailureHandler

**GitHub Issue Title:** `feat(audit): publish LOGIN_GOOGLE_FAILURE audit event on OAuth2 authentication failure`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2FailureHandler.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Test: `src/test/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2FailureHandlerTest.kt`

### Step 1: Create the failure handler

Spring Security's `AuthenticationFailureHandler` is called when OAuth2 login fails (e.g., user denies consent, Google returns an error, token exchange fails).

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2FailureHandler.kt
package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2FailureHandler(
    private val objectMapper: ObjectMapper,
    private val eventPublisher: ApplicationEventPublisher,
) : AuthenticationFailureHandler {

    private val logger = LoggerFactory.getLogger(GoogleOAuth2FailureHandler::class.java)

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        logger.warn("Google OAuth2 authentication failed: {}", exception.message)

        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.LOGIN_GOOGLE_FAILURE,
            ipAddress = request.remoteAddr,
            userAgent = request.getHeader("User-Agent"),
            metadata = mapOf("error" to exception.message),
        ))

        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(
            response.writer,
            ApiResponse.error("GOOGLE_AUTH_FAILED", exception.message ?: "Authentication failed"),
        )
    }
}
```

### Step 2: Wire into SecurityConfig

In `SecurityConfig.kt`, inject `GoogleOAuth2FailureHandler` and add `.failureHandler(...)`:

```kotlin
// Add constructor parameter:
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val googleOAuth2FailureHandler: GoogleOAuth2FailureHandler,
    private val jwtDecoder: JwtDecoder,
) {

// Change the oauth2Login line:
// Before:
            .oauth2Login { it.successHandler(googleOAuth2SuccessHandler) }
// After:
            .oauth2Login {
                it.successHandler(googleOAuth2SuccessHandler)
                it.failureHandler(googleOAuth2FailureHandler)
            }
```

Add import: `import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler`

### Step 3: Write the unit test

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2FailureHandlerTest.kt
package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.context.ApplicationEventPublisher
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.BadCredentialsException

class GoogleOAuth2FailureHandlerTest {

    private val objectMapper: ObjectMapper = jacksonObjectMapper()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val handler = GoogleOAuth2FailureHandler(objectMapper, eventPublisher)

    @Test
    fun `onAuthenticationFailure publishes LOGIN_GOOGLE_FAILURE and returns 401`() {
        val request = MockHttpServletRequest().apply {
            remoteAddr = "10.0.0.1"
            addHeader("User-Agent", "TestBrowser")
        }
        val response = MockHttpServletResponse()
        val exception = BadCredentialsException("Invalid token")

        handler.onAuthenticationFailure(request, response, exception)

        // Verify audit event
        val captured = slot<AuditDomainEvent>()
        verify(exactly = 1) { eventPublisher.publishEvent(capture(captured)) }
        assertThat(captured.captured.eventType).isEqualTo(AuditEvent.LOGIN_GOOGLE_FAILURE)
        assertThat(captured.captured.ipAddress).isEqualTo("10.0.0.1")
        assertThat(captured.captured.userAgent).isEqualTo("TestBrowser")
        assertThat(captured.captured.metadata).containsEntry("error", "Invalid token")

        // Verify HTTP response
        assertThat(response.status).isEqualTo(401)
        assertThat(response.contentType).isEqualTo("application/json")
        assertThat(response.contentAsString).contains("GOOGLE_AUTH_FAILED")
    }

    @Test
    fun `onAuthenticationFailure handles null user-agent`() {
        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()
        val exception = BadCredentialsException("Denied")

        handler.onAuthenticationFailure(request, response, exception)

        val captured = slot<AuditDomainEvent>()
        verify(exactly = 1) { eventPublisher.publishEvent(capture(captured)) }
        assertThat(captured.captured.userAgent).isNull()
        assertThat(response.status).isEqualTo(401)
    }
}
```

### Step 4: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 5: Commit

```bash
git add src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2FailureHandler.kt \
        src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
        src/test/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2FailureHandlerTest.kt
git commit -m "feat(audit): publish LOGIN_GOOGLE_FAILURE audit event on OAuth2 authentication failure (Closes #<issue>)"
```

---

## Summary

| Task | Type | Description |
|------|------|-------------|
| 1 | chore | `@JsonRawValue` on metadata — API returns nested JSON object |
| 2 | docs | Comment explaining dual events on first Google login |
| 3 | perf | Composite index `(event_type, user_id, created_at DESC)` |
| 4 | feat | `GoogleOAuth2FailureHandler` publishes `LOGIN_GOOGLE_FAILURE` |
