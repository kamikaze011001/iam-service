# Fix AuditLog Column Type Mappings Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Remove fragile `@ColumnTransformer(write = "CAST(? AS ...)")` hacks from `AuditLog` entity by fixing the root cause — a mismatch between PostgreSQL column types and JPA field mappings.

**Architecture:** Two columns need fixing. (1) `ip_address INET → TEXT` — we never use inet operators or range queries, just store/display plain strings. A Flyway migration alters the column and the entity drops the cast annotation. (2) `metadata JSONB` — keep JSONB for future query flexibility, but replace `@ColumnTransformer` with Hibernate 6's native `@JdbcTypeCode(SqlTypes.JSON)` which handles the type mapping correctly without casts.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Hibernate 6.6.8, PostgreSQL 16, Flyway, JUnit 5, MockK, Testcontainers

---

## Task 1: Migrate `ip_address` from INET to TEXT and fix entity mapping

**Files:**
- Create: `src/main/resources/db/migration/V4__fix_audit_ip_column_type.sql`
- Modify: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt`

### Step 1: Create Flyway migration

```sql
-- src/main/resources/db/migration/V4__fix_audit_ip_column_type.sql
-- Change ip_address from INET to TEXT.
-- We store IPs as plain strings in JPA and never use inet operators or range queries.
ALTER TABLE audit_logs ALTER COLUMN ip_address TYPE TEXT USING ip_address::TEXT;
```

### Step 2: Update AuditLog entity — remove inet workarounds

In `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt`:

**Change** the `ip_address` field from:

```kotlin
@Column(name = "ip_address", columnDefinition = "inet")
@ColumnTransformer(write = "CAST(? AS inet)")
val ipAddress: String?,
```

To:

```kotlin
@Column(name = "ip_address")
val ipAddress: String?,
```

Remove `columnDefinition = "inet"` and `@ColumnTransformer`. The column is now `TEXT` — a plain `String` maps directly.

### Step 3: Run tests

Run: `./gradlew clean test`
Expected: All tests PASS. The inet cast is gone, the migration alters the column, Testcontainers picks it up via Flyway.

---

## Task 2: Replace metadata JSONB `@ColumnTransformer` with `@JdbcTypeCode`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt`

### Step 1: Update AuditLog entity — use native Hibernate JSON type

In `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt`:

**Change** the `metadata` field from:

```kotlin
@Column(name = "metadata", columnDefinition = "jsonb")
@ColumnTransformer(write = "CAST(? AS jsonb)")
val metadata: String?,
```

To:

```kotlin
@JdbcTypeCode(SqlTypes.JSON)
@Column(name = "metadata", columnDefinition = "jsonb")
val metadata: String?,
```

**Update imports** — replace:
```kotlin
import org.hibernate.annotations.ColumnTransformer
```

With:
```kotlin
import org.hibernate.annotations.JdbcTypeCode
import org.hibernate.type.SqlTypes
```

### Step 2: Verify final AuditLog entity

The complete entity should look like this:

```kotlin
package com.aibles.iam.audit.domain.log

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.hibernate.annotations.JdbcTypeCode
import org.hibernate.type.SqlTypes
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

    @Column(name = "ip_address")
    val ipAddress: String?,

    @Column(name = "user_agent")
    val userAgent: String?,

    @JdbcTypeCode(SqlTypes.JSON)
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

### Step 3: Run tests

Run: `./gradlew clean test`
Expected: All 107 tests PASS. Hibernate now uses its native JSON type descriptor to send metadata as `PGobject(type=jsonb)` instead of a varchar with CAST.

### Step 4: Commit

```bash
git add src/main/resources/db/migration/V4__fix_audit_ip_column_type.sql \
        src/main/kotlin/com/aibles/iam/audit/domain/log/AuditLog.kt
git commit -m "fix(audit): replace ColumnTransformer casts with proper type mappings

- Migrate ip_address from INET to TEXT (V4 migration) — no inet operators used
- Replace metadata CAST with @JdbcTypeCode(SqlTypes.JSON) — native Hibernate 6 JSONB support
- Removes performance overhead of CAST() on every INSERT"
```

---

## Summary

| Column | Before (broken) | After (correct) |
|--------|----------------|-----------------|
| `ip_address` | `INET` + `@ColumnTransformer(write = "CAST(? AS inet)")` | `TEXT` + plain `@Column` |
| `metadata` | `JSONB` + `@ColumnTransformer(write = "CAST(? AS jsonb)")` | `JSONB` + `@JdbcTypeCode(SqlTypes.JSON)` |

**Why this is better:**
1. **No runtime CAST overhead** — Hibernate handles type binding natively
2. **No fragile Hibernate-specific hacks** — `@JdbcTypeCode` is the standard Hibernate 6 approach for JSON columns
3. **No subtle bugs** — `@ColumnTransformer` can break with batch inserts, criteria queries, and Hibernate version upgrades
4. **Future-proof** — JSONB column retained for potential future JSONB queries (e.g., `metadata @> '{"key": "value"}'`)
