# Fix Sprint 6 Audit Review Issues

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 3 issues found in the Sprint 6 final code review: JPQL null enum parameter, event listener failure propagation, and missing page/size validation.

**Architecture:** Replace JPQL `IS NULL` pattern with JPA Specification API for type-safe dynamic queries. Add try-catch + logging in the `@EventListener` so audit failures never break business operations. Add input clamping in the query use case.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Spring Data JPA `JpaSpecificationExecutor`, SLF4J logging, MockK

---

## Task 1: Replace JPQL `findFiltered` with JPA Specification API

**GitHub Issue Title:** `fix(audit): replace JPQL IS NULL pattern with JPA Specification for safe dynamic queries`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogRepository.kt`
- Create: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogSpecs.kt`
- Modify: `src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt`

### Step 1: Modify AuditLogRepository

Remove the `@Query findFiltered` method. Extend `JpaSpecificationExecutor<AuditLog>`.

```kotlin
// src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogRepository.kt
package com.aibles.iam.audit.domain.log

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.JpaSpecificationExecutor
import java.util.UUID

interface AuditLogRepository : JpaRepository<AuditLog, UUID>, JpaSpecificationExecutor<AuditLog>
```

### Step 2: Create AuditLogSpecs

Each filter is a separate `Specification<AuditLog>` factory function. They compose with `and()`. Only non-null filters are added.

```kotlin
// src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogSpecs.kt
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
```

### Step 3: Update QueryAuditLogsUseCase

Replace `repo.findFiltered(...)` with `repo.findAll(AuditLogSpecs.filtered(...), pageable)`. Add a `Sort.by(Sort.Direction.DESC, "createdAt")` to the `PageRequest` since the JPQL `ORDER BY` is gone.

```kotlin
// In QueryAuditLogsUseCase.kt, replace the execute body:
fun execute(query: Query): PageResponse<AuditLogItem> {
    val spec = AuditLogSpecs.filtered(
        eventType = query.eventType,
        userId = query.userId,
        from = query.from,
        to = query.to,
    )
    val pageable = PageRequest.of(query.page, query.size, Sort.by(Sort.Direction.DESC, "createdAt"))
    val page = auditLogRepository.findAll(spec, pageable)
    // ... rest unchanged (mapping to AuditLogItem)
}
```

Add import: `import org.springframework.data.domain.Sort`
Add import: `import com.aibles.iam.audit.domain.log.AuditLogSpecs`

### Step 4: Update QueryAuditLogsUseCaseTest

The mock expectations change from `repo.findFiltered(...)` to `repo.findAll(any<Specification<AuditLog>>(), any<Pageable>())`.

```kotlin
// Test 1: "execute returns paginated audit logs"
every {
    repo.findAll(any<Specification<AuditLog>>(), any<Pageable>())
} returns page

// Test 2: "execute passes filters to repository"
every {
    repo.findAll(any<Specification<AuditLog>>(), any<Pageable>())
} returns page
```

Add imports:
```kotlin
import org.springframework.data.domain.Pageable
import org.springframework.data.jpa.domain.Specification
```

### Step 5: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 6: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogRepository.kt \
        src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLogSpecs.kt \
        src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt \
        src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt
git commit -m "fix(audit): replace JPQL IS NULL pattern with JPA Specification for safe dynamic queries"
```

---

## Task 2: Add try-catch + logging in RecordAuditEventUseCase

**GitHub Issue Title:** `fix(audit): prevent audit listener failures from breaking business operations`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCaseTest.kt`

### Step 1: Add try-catch + SLF4J logger

```kotlin
// src/main/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCase.kt
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
```

### Step 2: Add test for failure case

Add a third test that verifies exceptions from `repo.save()` are caught and don't propagate:

```kotlin
@Test
fun `onAuditEvent swallows exception when save fails`() {
    every { repo.save(any()) } throws RuntimeException("DB down")

    val event = AuditDomainEvent(eventType = AuditEvent.USER_CREATED)

    // Should NOT throw — audit failures must not break business operations
    assertDoesNotThrow { useCase.onAuditEvent(event) }
}
```

Add import: `import org.junit.jupiter.api.assertDoesNotThrow`

### Step 3: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 4: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCase.kt \
        src/test/kotlin/com/aibles/iam/audit/usecase/RecordAuditEventUseCaseTest.kt
git commit -m "fix(audit): prevent audit listener failures from breaking business operations"
```

---

## Task 3: Add page/size input clamping in QueryAuditLogsUseCase

**GitHub Issue Title:** `fix(audit): clamp page/size parameters to safe bounds`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt`

### Step 1: Add clamping in execute()

At the start of `QueryAuditLogsUseCase.execute()`, clamp the values:

```kotlin
fun execute(query: Query): PageResponse<AuditLogItem> {
    val safePage = query.page.coerceAtLeast(0)
    val safeSize = query.size.coerceIn(1, 100)
    val spec = AuditLogSpecs.filtered(...)
    val pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "createdAt"))
    // ... rest unchanged
}
```

### Step 2: Add test for clamping

```kotlin
@Test
fun `execute clamps negative page and oversized size`() {
    val page = PageImpl(emptyList<AuditLog>(), PageRequest.of(0, 100), 0)

    every {
        repo.findAll(any<Specification<AuditLog>>(), any<Pageable>())
    } returns page

    val result = useCase.execute(
        QueryAuditLogsUseCase.Query(page = -5, size = 9999)
    )

    assertThat(result.page).isEqualTo(0)
    assertThat(result.size).isEqualTo(100)
}
```

### Step 3: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 4: Commit

```bash
git add src/main/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCase.kt \
        src/test/kotlin/com/aibles/iam/audit/usecase/QueryAuditLogsUseCaseTest.kt
git commit -m "fix(audit): clamp page/size parameters to safe bounds"
```

---

## Summary

| Task | Issue | Fix |
|------|-------|-----|
| 1 | JPQL `IS NULL` with enum param (Critical) | Replace with JPA Specification API |
| 2 | `@EventListener` failure propagation (Critical) | Try-catch + SLF4J logging |
| 3 | No page/size validation (Important) | Clamp to safe bounds (`page >= 0`, `size 1..100`) |

All 3 tasks modify audit BC code only. No cross-BC changes needed.
