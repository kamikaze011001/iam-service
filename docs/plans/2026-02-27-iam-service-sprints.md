# IAM Service — Sprint Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan.
> An issue is NOT done until every item in its **Definition of Done** checklist is ticked with evidence.

**Goal:** Build a production-grade single-tenant IAM service with Google OAuth2, Passkey, OAuth2/OIDC SSO, and audit logging.

**Architecture:** Modular monolith, bounded contexts, use-case driven. JPA entity as domain. Aggregate-based sub-packages.

**Tech Stack:** Kotlin 2.x, Java 24, Spring Boot 3.4.x, Virtual Threads, PostgreSQL 16, Redis 7, Spring Authorization Server 1.4.x, webauthn4j-spring-security.

**Workflow:** Complete ALL issues in a sprint (including verification) before starting the next sprint.

---

## Global Definition of Done

Every issue must satisfy ALL of the following before it is considered complete:

- [ ] `./gradlew build` passes with zero errors and zero warnings
- [ ] `./gradlew test` passes — zero failures, zero errors
- [ ] Every new class/function has at least one happy-path test and one failure-path test
- [ ] Issue-specific verification commands executed and output matches expected (see each issue)
- [ ] No `TODO` or `FIXME` left in any implementation file
- [ ] PR opened referencing the issue: `Closes #<N>`
- [ ] PR description includes copy-pasted terminal output proving tests pass

---

## Sprint 1 — Foundation

---

### Issue 1: Initialize Gradle project

**Labels:** `sprint-1`, `setup`

**Files to create:**
- `build.gradle.kts`
- `settings.gradle.kts`
- `src/main/kotlin/com/aibles/iam/IamApplication.kt`
- `src/main/resources/application.yml`
- Empty package stubs for all bounded contexts

**`build.gradle.kts`:**
```kotlin
plugins {
    kotlin("jvm") version "2.1.0"
    kotlin("plugin.spring") version "2.1.0"
    kotlin("plugin.jpa") version "2.1.0"
    id("org.springframework.boot") version "3.4.3"
    id("io.spring.dependency-management") version "1.1.7"
    jacoco
}

group = "com.aibles"
version = "0.0.1-SNAPSHOT"
java { toolchain { languageVersion = JavaLanguageVersion.of(24) } }

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.4.2")
    implementation("com.webauthn4j:webauthn4j-spring-security-core:0.9.3.RELEASE")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("com.bucket4j:bucket4j-core:8.10.1")
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.3")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("org.postgresql:postgresql")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("io.mockk:mockk:1.13.13")
    testImplementation("com.ninja-squad:springmockk:4.0.2")
    testImplementation("org.testcontainers:postgresql")
    testImplementation("org.testcontainers:junit-jupiter")
}

kotlin { compilerOptions { freeCompilerArgs.addAll("-Xjsr305=strict") } }
tasks.withType<Test> { useJUnitPlatform() }
```

**`application.yml`:**
```yaml
spring:
  threads:
    virtual:
      enabled: true
  datasource:
    url: ${DB_URL:jdbc:postgresql://localhost:5432/iam}
    username: ${DB_USERNAME:iam}
    password: ${DB_PASSWORD:iam}
    hikari:
      maximum-pool-size: 20
  jpa:
    hibernate:
      ddl-auto: validate
    open-in-view: false
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
  flyway:
    enabled: true
    locations: classpath:db/migration
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID:placeholder}
            client-secret: ${GOOGLE_CLIENT_SECRET:placeholder}
            scope: openid,email,profile
server:
  port: ${PORT:8080}
management:
  endpoints:
    web:
      exposure:
        include: health,info
```

**Verification:**
```bash
# 1. Build
./gradlew build
# Expected: BUILD SUCCESSFUL

# 2. Start (with docker compose up -d first)
./gradlew bootRun &
sleep 10
curl -s http://localhost:8080/actuator/health
# Expected: {"status":"UP"}
```

**Definition of Done:**
- [ ] `./gradlew build` → `BUILD SUCCESSFUL`
- [ ] `GET /actuator/health` → `{"status":"UP"}`
- [ ] All bounded context packages exist in source tree

---

### Issue 2: Docker Compose + environment setup

**Labels:** `sprint-1`, `setup`

**Files to create:** `docker-compose.yml`, `.env.example`, `.gitignore`

**`docker-compose.yml`:**
```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: iam
      POSTGRES_USER: iam
      POSTGRES_PASSWORD: iam
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U iam"]
      interval: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s

volumes:
  postgres_data:
```

**`.env.example`:**
```
DB_URL=jdbc:postgresql://localhost:5432/iam
DB_USERNAME=iam
DB_PASSWORD=iam
REDIS_HOST=localhost
REDIS_PORT=6379
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
JWT_PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----
JWT_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----
APP_BASE_URL=http://localhost:8080
ALLOWED_ORIGINS=http://localhost:3000
```

**`.gitignore` must include:** `.env`, `*.jar`, `build/`, `.gradle/`

**Verification:**
```bash
docker compose up -d
docker compose ps
# Expected: postgres and redis both show "healthy"

docker compose exec postgres pg_isready -U iam
# Expected: /var/run/postgresql:5432 - accepting connections

docker compose exec redis redis-cli ping
# Expected: PONG
```

**Definition of Done:**
- [ ] `docker compose up -d` starts both services healthy
- [ ] `.env` is listed in `.gitignore`
- [ ] `.env.example` documents all required variables with placeholder values
- [ ] `git status` confirms `.env` is not tracked

---

### Issue 3: Flyway baseline migration

**Labels:** `sprint-1`, `database`

**File to create:** `src/main/resources/db/migration/V1__init_schema.sql`

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    display_name  TEXT,
    google_sub    TEXT UNIQUE,
    roles         TEXT[] NOT NULL DEFAULT '{USER}',
    status        TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE passkey_credentials (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    BYTEA UNIQUE NOT NULL,
    public_key_cose  BYTEA NOT NULL,
    sign_counter     BIGINT NOT NULL DEFAULT 0,
    aaguid           UUID,
    display_name     TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at     TIMESTAMPTZ
);
CREATE INDEX idx_passkey_user_id ON passkey_credentials(user_id);

CREATE TABLE audit_logs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type   TEXT NOT NULL,
    user_id      UUID,
    actor_id     UUID,
    ip_address   INET,
    user_agent   TEXT,
    metadata     JSONB,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_created  ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_event    ON audit_logs(event_type);
```

**Verification:**
```bash
./gradlew bootRun &
sleep 10

# Confirm Flyway applied migration
docker compose exec postgres psql -U iam -d iam -c "\dt"
# Expected: lists users, user_roles, passkey_credentials, audit_logs, flyway_schema_history

# Confirm table structure
docker compose exec postgres psql -U iam -d iam -c "\d users"
# Expected: shows all columns with correct types
```

**Definition of Done:**
- [ ] `./gradlew bootRun` applies migration with no errors in logs
- [ ] All 4 tables exist in PostgreSQL
- [ ] `flyway_schema_history` shows V1 as `success=true`

---

### Issue 4: Shared error + response layer

**Labels:** `sprint-1`, `shared`

**Files to create:**
- `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`
- `src/main/kotlin/com/aibles/iam/shared/error/BaseException.kt`
- `src/main/kotlin/com/aibles/iam/shared/error/AppExceptions.kt`
- `src/main/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandler.kt`
- `src/main/kotlin/com/aibles/iam/shared/response/ApiResponse.kt`
- `src/main/kotlin/com/aibles/iam/shared/response/ErrorDetail.kt`
- `src/main/kotlin/com/aibles/iam/shared/pagination/PageResponse.kt`
- `src/test/kotlin/com/aibles/iam/shared/error/ErrorCodeTest.kt`
- `src/test/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandlerTest.kt`

**`ErrorCode.kt`:**
```kotlin
package com.aibles.iam.shared.error

import org.springframework.http.HttpStatus

enum class ErrorCode(val httpStatus: HttpStatus) {
    BAD_REQUEST(HttpStatus.BAD_REQUEST),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED),
    FORBIDDEN(HttpStatus.FORBIDDEN),
    CONFLICT(HttpStatus.CONFLICT),
    VALIDATION_ERROR(HttpStatus.UNPROCESSABLE_ENTITY),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND),
    USER_EMAIL_CONFLICT(HttpStatus.CONFLICT),
    USER_DISABLED(HttpStatus.FORBIDDEN),
    GOOGLE_TOKEN_INVALID(HttpStatus.UNAUTHORIZED),
    PASSKEY_NOT_FOUND(HttpStatus.NOT_FOUND),
    PASSKEY_COUNTER_INVALID(HttpStatus.UNAUTHORIZED),
    PASSKEY_CHALLENGE_EXPIRED(HttpStatus.BAD_REQUEST),
    PASSKEY_ATTESTATION_FAILED(HttpStatus.BAD_REQUEST),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED),
    TOKEN_REVOKED(HttpStatus.UNAUTHORIZED),
}
```

**`BaseException.kt`:**
```kotlin
package com.aibles.iam.shared.error

import org.springframework.http.HttpStatus

abstract class BaseException(
    val errorCode: ErrorCode,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    val httpStatus: HttpStatus get() = errorCode.httpStatus
}
```

**`AppExceptions.kt`:**
```kotlin
package com.aibles.iam.shared.error

class NotFoundException(message: String, errorCode: ErrorCode)     : BaseException(errorCode, message)
class ConflictException(message: String, errorCode: ErrorCode)      : BaseException(errorCode, message)
class UnauthorizedException(message: String, errorCode: ErrorCode)  : BaseException(errorCode, message)
class ForbiddenException(message: String, errorCode: ErrorCode)     : BaseException(errorCode, message)
class BadRequestException(message: String, errorCode: ErrorCode)    : BaseException(errorCode, message)
class ValidationException(
    message: String,
    val fields: Map<String, String> = emptyMap(),
) : BaseException(ErrorCode.VALIDATION_ERROR, message)
```

**`ApiResponse.kt`:**
```kotlin
package com.aibles.iam.shared.response

import java.time.Instant

data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val error: ErrorDetail? = null,
    val timestamp: Instant = Instant.now(),
) {
    companion object {
        fun <T> ok(data: T): ApiResponse<T> = ApiResponse(success = true, data = data)
        fun error(code: String, message: String): ApiResponse<Nothing> =
            ApiResponse(success = false, error = ErrorDetail(code, message))
    }
}

data class ErrorDetail(val code: String, val message: String)
```

**`GlobalExceptionHandler.kt`:**
```kotlin
package com.aibles.iam.shared.error

import com.aibles.iam.shared.response.ApiResponse
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(BaseException::class)
    fun handleBase(e: BaseException): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.status(e.httpStatus)
            .body(ApiResponse.error(e.errorCode.name, e.message ?: "Error"))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(e: MethodArgumentNotValidException): ResponseEntity<ApiResponse<Nothing>> {
        val msg = e.bindingResult.fieldErrors.joinToString("; ") {
            "${it.field}: ${it.defaultMessage}"
        }
        return ResponseEntity.status(422)
            .body(ApiResponse.error(ErrorCode.VALIDATION_ERROR.name, msg))
    }

    @ExceptionHandler(Exception::class)
    fun handleUnexpected(e: Exception): ResponseEntity<ApiResponse<Nothing>> =
        ResponseEntity.internalServerError()
            .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.name, "Unexpected error"))
}
```

**`ErrorCodeTest.kt`:**
```kotlin
class ErrorCodeTest {
    @Test fun `USER_NOT_FOUND maps to 404`() =
        assertThat(ErrorCode.USER_NOT_FOUND.httpStatus.value()).isEqualTo(404)

    @Test fun `TOKEN_INVALID maps to 401`() =
        assertThat(ErrorCode.TOKEN_INVALID.httpStatus.value()).isEqualTo(401)

    @Test fun `USER_EMAIL_CONFLICT maps to 409`() =
        assertThat(ErrorCode.USER_EMAIL_CONFLICT.httpStatus.value()).isEqualTo(409)

    @Test fun `exception httpStatus derived from errorCode`() {
        val ex = NotFoundException("not found", ErrorCode.USER_NOT_FOUND)
        assertThat(ex.httpStatus.value()).isEqualTo(404)
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }

    @Test fun `ValidationException always uses VALIDATION_ERROR code`() {
        val ex = ValidationException("invalid", mapOf("email" to "required"))
        assertThat(ex.errorCode).isEqualTo(ErrorCode.VALIDATION_ERROR)
        assertThat(ex.httpStatus.value()).isEqualTo(422)
    }
}
```

**`GlobalExceptionHandlerTest.kt`** — use `@WebMvcTest` with a test controller that throws each exception type. Verify response body shape matches `ApiResponse` contract.

**Verification:**
```bash
# Unit tests
./gradlew test --tests "com.aibles.iam.shared.*"
# Expected: BUILD SUCCESSFUL, all tests green

# Start app and test error shape
./gradlew bootRun &
sleep 10

# Hit a non-existent endpoint — should return consistent error shape
curl -s http://localhost:8080/api/v1/nonexistent | jq .
# Expected:
# {
#   "success": false,
#   "data": null,
#   "error": { "code": "...", "message": "..." },
#   "timestamp": "..."
# }
```

**Definition of Done:**
- [ ] `./gradlew test --tests "com.aibles.iam.shared.*"` → all pass
- [ ] Every `ErrorCode` entry has a corresponding test asserting correct HTTP status
- [ ] `GlobalExceptionHandlerTest` covers: `BaseException`, `MethodArgumentNotValidException`, unexpected `Exception`
- [ ] Error responses always match `ApiResponse` shape — verified by `jq` output above

---

## Sprint 2 — Identity Bounded Context

---

### Issue 5: User aggregate — entity + repository

**Labels:** `sprint-2`, `identity`

**Files to create:**
- `src/main/kotlin/com/aibles/iam/identity/domain/user/UserStatus.kt`
- `src/main/kotlin/com/aibles/iam/identity/domain/user/User.kt`
- `src/main/kotlin/com/aibles/iam/identity/domain/user/UserRepository.kt`
- `src/test/kotlin/com/aibles/iam/identity/domain/user/UserTest.kt`

**`User.kt`:**
```kotlin
@Entity
@Table(name = "users")
class User private constructor(
    @Id val id: UUID = UUID.randomUUID(),
    @Column(unique = true, nullable = false) val email: String,
    var displayName: String? = null,
    @Column(unique = true) val googleSub: String? = null,
    @Enumerated(EnumType.STRING) var status: UserStatus = UserStatus.ACTIVE,
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = [JoinColumn(name = "user_id")])
    @Column(name = "role") var roles: MutableSet<String> = mutableSetOf("USER"),
    val createdAt: Instant = Instant.now(),
    var updatedAt: Instant = Instant.now(),
    var lastLoginAt: Instant? = null,
) {
    companion object {
        fun create(email: String, displayName: String? = null, googleSub: String? = null): User {
            require(email.isNotBlank() && email.contains("@")) { "Invalid email: $email" }
            return User(email = email.lowercase().trim(), displayName = displayName?.trim(), googleSub = googleSub)
        }
    }

    fun updateProfile(newDisplayName: String) { displayName = newDisplayName.trim(); updatedAt = Instant.now() }
    fun disable() { status = UserStatus.DISABLED; updatedAt = Instant.now() }
    fun enable()  { status = UserStatus.ACTIVE;   updatedAt = Instant.now() }
    fun recordLogin() { lastLoginAt = Instant.now(); updatedAt = Instant.now() }
    fun isActive() = status == UserStatus.ACTIVE
}
```

**`UserTest.kt`:**
```kotlin
class UserTest {
    @Test fun `create lowercases and trims email`() =
        assertThat(User.create("  TEST@EXAMPLE.COM  ").email).isEqualTo("test@example.com")

    @Test fun `create rejects blank email`() =
        assertThrows<IllegalArgumentException> { User.create("") }

    @Test fun `create rejects email without at sign`() =
        assertThrows<IllegalArgumentException> { User.create("notanemail") }

    @Test fun `disable sets DISABLED status`() {
        val user = User.create("a@b.com").also { it.disable() }
        assertThat(user.isActive()).isFalse()
    }

    @Test fun `enable restores ACTIVE after disable`() {
        val user = User.create("a@b.com").also { it.disable(); it.enable() }
        assertThat(user.isActive()).isTrue()
    }

    @Test fun `updateProfile trims display name`() {
        val user = User.create("a@b.com").also { it.updateProfile("  Alice  ") }
        assertThat(user.displayName).isEqualTo("Alice")
    }

    @Test fun `recordLogin sets lastLoginAt`() {
        val user = User.create("a@b.com").also { it.recordLogin() }
        assertThat(user.lastLoginAt).isNotNull()
    }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.identity.domain.user.*"
# Expected: BUILD SUCCESSFUL, 7 tests passed

# Confirm JPA mapping works against real DB
./gradlew bootRun &
sleep 10
# App starts without Hibernate schema errors → JPA entity maps correctly to V1 migration
```

**Definition of Done:**
- [ ] All 7 `UserTest` cases pass
- [ ] App starts without JPA/Hibernate errors (entity maps correctly to migration schema)
- [ ] `UserRepository` interface compiles — Spring Data JPA generates implementation at runtime

---

### Issue 6: User CRUD use cases

**Labels:** `sprint-2`, `identity`

**Files to create (one file per use case + one test file per use case):**
- `CreateUserUseCase.kt` + `CreateUserUseCaseTest.kt`
- `GetUserUseCase.kt` + `GetUserUseCaseTest.kt`
- `UpdateUserUseCase.kt` + `UpdateUserUseCaseTest.kt`
- `ChangeUserStatusUseCase.kt` + `ChangeUserStatusUseCaseTest.kt`
- `DeleteUserUseCase.kt` + `DeleteUserUseCaseTest.kt`

All under `identity/usecase/` and `test/.../identity/usecase/`.

All tests use MockK — no Spring context needed:
```kotlin
class CreateUserUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val useCase = CreateUserUseCase(repo)

    @Test fun `creates and saves user`() {
        every { repo.existsByEmail("a@b.com") } returns false
        every { repo.save(any()) } answers { firstArg() }
        val result = useCase.execute(CreateUserUseCase.Command("a@b.com", "Alice", null))
        assertThat(result.user.email).isEqualTo("a@b.com")
        verify(exactly = 1) { repo.save(any()) }
    }

    @Test fun `throws ConflictException for duplicate email`() {
        every { repo.existsByEmail(any()) } returns true
        val ex = assertThrows<ConflictException> {
            useCase.execute(CreateUserUseCase.Command("a@b.com", "Alice", null))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_EMAIL_CONFLICT)
    }
}

class GetUserUseCaseTest {
    private val repo = mockk<UserRepository>()
    private val useCase = GetUserUseCase(repo)

    @Test fun `returns user when found`() {
        val user = User.create("a@b.com")
        every { repo.findById(user.id) } returns Optional.of(user)
        assertThat(useCase.execute(GetUserUseCase.Query(user.id))).isEqualTo(user)
    }

    @Test fun `throws NotFoundException with USER_NOT_FOUND code`() {
        val id = UUID.randomUUID()
        every { repo.findById(id) } returns Optional.empty()
        val ex = assertThrows<NotFoundException> { useCase.execute(GetUserUseCase.Query(id)) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.identity.usecase.*"
# Expected: BUILD SUCCESSFUL, all tests green (minimum 2 tests per use case = 10 tests)
```

**Definition of Done:**
- [ ] Each use case has ≥ 1 happy-path test and ≥ 1 failure-path test
- [ ] Every thrown exception uses a typed `ErrorCode` — no string codes
- [ ] `./gradlew test --tests "com.aibles.iam.identity.usecase.*"` → all pass
- [ ] Use cases have zero imports from `api/` package

---

### Issue 7: Users REST API

**Labels:** `sprint-2`, `identity`, `api`

**Files to create:**
- `identity/api/dto/UserResponse.kt`
- `identity/api/dto/UpdateUserRequest.kt`
- `identity/api/dto/ChangeStatusRequest.kt`
- `identity/api/UsersController.kt`
- `src/test/kotlin/com/aibles/iam/identity/api/UsersControllerTest.kt`

**`UsersController.kt`** exposes:
```
GET    /api/v1/users/me             → ApiResponse<UserResponse>
PATCH  /api/v1/users/me             → ApiResponse<UserResponse>
GET    /api/v1/users                → ApiResponse<PageResponse<UserResponse>>  (ADMIN)
GET    /api/v1/users/{id}           → ApiResponse<UserResponse>               (ADMIN)
PATCH  /api/v1/users/{id}/status    → ApiResponse<UserResponse>               (ADMIN)
DELETE /api/v1/users/{id}           → 204 No Content                          (ADMIN)
```

Controllers return `ApiResponse.ok(...)` — never call repositories directly.

**`UsersControllerTest.kt`** uses `@WebMvcTest(UsersController::class)` + `MockkBean` for use cases.

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.identity.api.*"
# Expected: BUILD SUCCESSFUL

# Start app (with valid DB), create a test user manually in DB, then:
TOKEN="<valid-jwt>"
curl -s http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer $TOKEN" | jq .
# Expected:
# {
#   "success": true,
#   "data": { "id": "...", "email": "...", "roles": ["USER"], "status": "ACTIVE", ... },
#   "error": null,
#   "timestamp": "..."
# }

# Test not-found error shape
curl -s http://localhost:8080/api/v1/users/00000000-0000-0000-0000-000000000000 \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
# Expected:
# { "success": false, "data": null, "error": { "code": "USER_NOT_FOUND", "message": "..." }, ... }
```

**Definition of Done:**
- [ ] `./gradlew test --tests "com.aibles.iam.identity.api.*"` → all pass
- [ ] `GET /api/v1/users/me` returns `ApiResponse` shape confirmed by `jq` output
- [ ] `GET /api/v1/users/{nonexistentId}` returns `error.code = "USER_NOT_FOUND"`
- [ ] Controllers have zero direct `UserRepository` imports — all via use cases

---

## Sprint 3 — Google OAuth2 + Token Management

---

### Issue 8: JWT service + RSA key loading

**Labels:** `sprint-3`, `authorization`

**Files to create:**
- `shared/config/JwtProperties.kt`
- `authorization/infra/JwtService.kt`
- `src/test/kotlin/com/aibles/iam/authorization/infra/JwtServiceTest.kt`

Add to `application.yml`:
```yaml
jwt:
  private-key: ${JWT_PRIVATE_KEY}
  public-key: ${JWT_PUBLIC_KEY}
  access-token-ttl-minutes: ${JWT_TTL_MINUTES:15}
```

`JwtService` must: generate RS256 JWT with `sub`, `email`, `roles`, `iat`, `exp` claims; validate and decode; reject tokens with wrong algorithm, wrong signature, or expired.

**`JwtServiceTest.kt`:**
```kotlin
class JwtServiceTest {
    // generate a test RSA key pair inline for tests
    private val keyPair = generateRsaKeyPair()
    private val service = JwtService(JwtProperties(
        privateKey = encodePrivateKey(keyPair.private),
        publicKey = encodePublicKey(keyPair.public),
        accessTokenTtlMinutes = 15,
    ))

    @Test fun `generated token contains correct claims`() {
        val userId = UUID.randomUUID()
        val token = service.generateAccessToken(userId, "a@b.com", setOf("USER"))
        val decoded = service.validate(token)
        assertThat(decoded.subject).isEqualTo(userId.toString())
        assertThat(decoded.getClaim("email").asString()).isEqualTo("a@b.com")
    }

    @Test fun `tampered token is rejected`() {
        val token = service.generateAccessToken(UUID.randomUUID(), "a@b.com", setOf("USER"))
        val tampered = token.dropLast(5) + "XXXXX"
        assertThrows<UnauthorizedException> { service.validate(tampered) }
    }

    @Test fun `expired token is rejected`() {
        val shortLivedService = JwtService(props.copy(accessTokenTtlMinutes = 0))
        val token = shortLivedService.generateAccessToken(UUID.randomUUID(), "a@b.com", setOf("USER"))
        Thread.sleep(1000)
        assertThrows<UnauthorizedException> { shortLivedService.validate(token) }
    }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.JwtServiceTest"
# Expected: BUILD SUCCESSFUL, 3 tests passed

# Generate real key pair and set in .env, then:
./gradlew bootRun &
sleep 10
curl -s http://localhost:8080/actuator/health
# Expected: {"status":"UP"} — confirms RSA key loading works
```

**Definition of Done:**
- [ ] All 3 `JwtServiceTest` cases pass
- [ ] App starts without key-loading errors when `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` are set in `.env`
- [ ] Tampered token test passes — rejects with `UnauthorizedException(TOKEN_INVALID)`

---

### Issue 9: Redis token store

**Labels:** `sprint-3`, `authorization`

**Files to create:**
- `authorization/domain/token/TokenStore.kt`
- `authorization/infra/RedisTokenStore.kt`
- `src/test/kotlin/com/aibles/iam/authorization/infra/RedisTokenStoreTest.kt`

```kotlin
interface TokenStore {
    fun storeRefreshToken(token: String, userId: UUID, ttl: Duration)
    fun validateAndConsume(token: String): UUID  // deletes atomically; throws TOKEN_INVALID if missing
    fun revokeAllForUser(userId: UUID)
}
```

`RedisTokenStore`: key = `rt:{token}`, value = `userId.toString()`.

**`RedisTokenStoreTest.kt`** uses Testcontainers Redis:
```kotlin
@Testcontainers
class RedisTokenStoreTest {
    @Container companion object { val redis = GenericContainer<Nothing>("redis:7-alpine").withExposedPorts(6379) }

    @Test fun `store and consume returns correct userId`() { ... }
    @Test fun `consume twice throws UnauthorizedException with TOKEN_INVALID`() { ... }
    @Test fun `expired token throws UnauthorizedException`() { /* store with 1s TTL, sleep 2s */ }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.RedisTokenStoreTest"
# Expected: BUILD SUCCESSFUL, 3 tests passed (Testcontainers spins up real Redis)
```

**Definition of Done:**
- [ ] All 3 `RedisTokenStoreTest` cases pass using real Redis via Testcontainers
- [ ] Second consume of same token throws `UnauthorizedException` with code `TOKEN_INVALID`
- [ ] Expired token throws `UnauthorizedException` with code `TOKEN_INVALID`

---

### Issue 10: IssueTokenUseCase + RefreshTokenUseCase + RevokeTokenUseCase

**Labels:** `sprint-3`, `authorization`

**Files to create (+ test per use case):**
- `authorization/usecase/IssueTokenUseCase.kt`
- `authorization/usecase/RefreshTokenUseCase.kt`
- `authorization/usecase/RevokeTokenUseCase.kt`

```kotlin
@Component
class RefreshTokenUseCase(
    private val tokenStore: TokenStore,
    private val getUser: GetUserUseCase,
    private val issueToken: IssueTokenUseCase,
) {
    data class Command(val refreshToken: String)

    fun execute(command: Command): IssueTokenUseCase.Result {
        val userId = tokenStore.validateAndConsume(command.refreshToken)
        val user = getUser.execute(GetUserUseCase.Query(userId))
        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)
        return issueToken.execute(IssueTokenUseCase.Command(user))
    }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authorization.usecase.*"
# Expected: all pass

# Token rotation integration smoke test (requires running app + DB + Redis):
# 1. Get tokens via login
# 2. Use refresh token → get new tokens
# 3. Use OLD refresh token → must fail with TOKEN_INVALID
```

**Definition of Done:**
- [ ] All use case tests pass
- [ ] `RefreshTokenUseCaseTest`: disabled user returns `ForbiddenException(USER_DISABLED)`
- [ ] `RefreshTokenUseCaseTest`: consumed token returns `UnauthorizedException(TOKEN_INVALID)`
- [ ] `RevokeTokenUseCaseTest`: revoked token cannot be consumed (throws TOKEN_REVOKED or TOKEN_INVALID)

---

### Issue 11: Google OAuth2 post-login handler + SecurityConfig

**Labels:** `sprint-3`, `authentication`

**Files to create:**
- `authentication/usecase/LoginWithGoogleUseCase.kt`
- `authentication/infra/GoogleOAuth2SuccessHandler.kt`
- `shared/config/SecurityConfig.kt`

`LoginWithGoogleUseCase`:
1. Extract `googleSub`, `email`, `name` from Spring Security `OidcUser`
2. Find user by `googleSub` or `email`; create if not found (via `CreateUserUseCase`)
3. Call `user.recordLogin()`; save
4. Call `IssueTokenUseCase`
5. Return tokens

`GoogleOAuth2SuccessHandler` implements `AuthenticationSuccessHandler`:
- Calls `LoginWithGoogleUseCase`
- Writes `ApiResponse.ok(TokenResponse(...))` JSON to `HttpServletResponse`

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.LoginWithGoogleUseCaseTest"
# Expected: all pass

# Manual flow (requires valid Google OAuth2 credentials in .env):
# 1. Open browser: http://localhost:8080/oauth2/authorize?...
# 2. Complete Google login
# 3. Verify response body contains:
#    { "success": true, "data": { "accessToken": "...", "refreshToken": "...", "expiresIn": 900 } }
```

**Definition of Done:**
- [ ] `LoginWithGoogleUseCaseTest`: new user is created on first login
- [ ] `LoginWithGoogleUseCaseTest`: existing user is returned on second login (no duplicate)
- [ ] `LoginWithGoogleUseCaseTest`: disabled user throws `ForbiddenException(USER_DISABLED)`
- [ ] Manual Google login flow returns `ApiResponse` token shape

---

### Issue 12: Logout endpoint

**Labels:** `sprint-3`, `authentication`

**File to create/modify:** `authentication/api/AuthController.kt`

```
POST /api/v1/auth/logout   body: { "refreshToken": "..." }   → 204 No Content
```

Calls `RevokeTokenUseCase`. No response body on success.

**Verification:**
```bash
# 1. Get a refresh token via login
# 2. Logout
curl -s -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<token>"}' -w "%{http_code}"
# Expected: 204

# 3. Try to use the revoked refresh token
curl -s -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=refresh_token&refresh_token=<token>" | jq .
# Expected: { "success": false, "error": { "code": "TOKEN_INVALID", ... } }
```

**Definition of Done:**
- [ ] `POST /api/v1/auth/logout` with valid token → 204
- [ ] Using the same refresh token after logout → `TOKEN_INVALID` error
- [ ] `AuthControllerTest` covers both cases

---

## Sprint 4 — Passkey / WebAuthn

---

### Issue 13: PasskeyCredential aggregate

**Labels:** `sprint-4`, `authentication`

**Files to create:**
- `authentication/domain/passkey/PasskeyCredential.kt`
- `authentication/domain/passkey/PasskeyCredentialRepository.kt`
- `authentication/domain/passkey/AuthChallenge.kt`
- `src/test/kotlin/.../passkey/PasskeyCredentialTest.kt`

**`PasskeyCredentialTest.kt`:**
```kotlin
class PasskeyCredentialTest {
    private fun credential(counter: Long = 0) = PasskeyCredential(
        userId = UUID.randomUUID(),
        credentialId = byteArrayOf(1, 2, 3),
        publicKeyCose = byteArrayOf(4, 5, 6),
        signCounter = counter,
    )

    @Test fun `verifyAndIncrementCounter accepts higher counter`() {
        val c = credential(5)
        c.verifyAndIncrementCounter(6)
        assertThat(c.signCounter).isEqualTo(6)
    }

    @Test fun `verifyAndIncrementCounter rejects equal counter (replay)`() {
        val ex = assertThrows<UnauthorizedException> { credential(5).verifyAndIncrementCounter(5) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }

    @Test fun `verifyAndIncrementCounter rejects lower counter (replay)`() {
        val ex = assertThrows<UnauthorizedException> { credential(5).verifyAndIncrementCounter(3) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authentication.domain.passkey.*"
# Expected: BUILD SUCCESSFUL, 3 tests passed
```

**Definition of Done:**
- [ ] All 3 `PasskeyCredentialTest` cases pass
- [ ] App starts without JPA errors (entity maps to `passkey_credentials` table)
- [ ] Counter replay rejected with `PASSKEY_COUNTER_INVALID` error code

---

### Issue 14: WebAuthn4J config + Redis challenge store

**Labels:** `sprint-4`, `authentication`

**Files to create:**
- `shared/config/WebAuthnConfig.kt`
- `authentication/infra/RedisChallengeStore.kt`

`RedisChallengeStore`: key = `wc:{sessionId}`, TTL = 5 minutes. `getAndDelete` for one-time use.

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisChallengeStoreTest"
# Expected: store challenge, retrieve once succeeds, retrieve again throws PASSKEY_CHALLENGE_EXPIRED

./gradlew bootRun &
sleep 10
curl -s http://localhost:8080/actuator/health
# Expected: {"status":"UP"} — WebAuthn4J beans loaded without error
```

**Definition of Done:**
- [ ] `RedisChallengeStoreTest`: challenge retrieved once → success; second retrieval → `PASSKEY_CHALLENGE_EXPIRED`
- [ ] App starts without WebAuthn bean wiring errors

---

### Issue 15: Passkey registration use cases

**Labels:** `sprint-4`, `authentication`

**Files to create:**
- `authentication/usecase/RegisterPasskeyStartUseCase.kt`
- `authentication/usecase/RegisterPasskeyFinishUseCase.kt`
- Tests for both

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.RegisterPasskey*"
# Expected: all pass

# Integration smoke (requires browser with WebAuthn support):
# POST /api/v1/auth/passkey/register/start → returns options JSON
# POST /api/v1/auth/passkey/register/finish with browser response → 200 + credential saved in DB
docker compose exec postgres psql -U iam -d iam -c "SELECT id, user_id, display_name FROM passkey_credentials;"
# Expected: row appears after successful registration
```

**Definition of Done:**
- [ ] `RegisterPasskeyStartUseCaseTest`: returns options JSON, challenge stored in Redis
- [ ] `RegisterPasskeyFinishUseCaseTest`: expired challenge throws `PASSKEY_CHALLENGE_EXPIRED`
- [ ] `RegisterPasskeyFinishUseCaseTest`: invalid attestation throws `PASSKEY_ATTESTATION_FAILED`
- [ ] DB row confirmed after manual smoke test

---

### Issue 16: Passkey authentication use cases

**Labels:** `sprint-4`, `authentication`

**Files to create:**
- `authentication/usecase/AuthenticatePasskeyStartUseCase.kt`
- `authentication/usecase/AuthenticatePasskeyFinishUseCase.kt`
- Tests for both

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.AuthenticatePasskey*"
# Expected: all pass — including replay attack test (counter not incremented → rejected)
```

**Definition of Done:**
- [ ] Happy path: valid assertion → JWT + refresh token returned in `ApiResponse`
- [ ] Replay attack: counter ≤ stored → `PASSKEY_COUNTER_INVALID`
- [ ] Unknown credential → `PASSKEY_NOT_FOUND`
- [ ] Expired challenge → `PASSKEY_CHALLENGE_EXPIRED`

---

### Issue 17: Passkey REST API

**Labels:** `sprint-4`, `authentication`, `api`

**Files to create:**
- `authentication/api/PasskeyController.kt`
- `authentication/api/dto/` (all request/response DTOs)

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.authentication.api.PasskeyControllerTest"
# Expected: all pass

# Smoke test list endpoint
curl -s http://localhost:8080/api/v1/auth/passkey/credentials \
  -H "Authorization: Bearer $TOKEN" | jq .
# Expected: { "success": true, "data": [...], ... }
```

**Definition of Done:**
- [ ] All 6 endpoints respond with correct `ApiResponse` shape
- [ ] `PasskeyControllerTest` covers each endpoint with mock use cases
- [ ] Delete endpoint returns 204; listing after delete shows credential removed

---

## Sprint 5 — OAuth2/OIDC Authorization Server

---

### Issue 18: Spring Authorization Server base config

**Labels:** `sprint-5`, `authorization`

**Files to create:**
- `authorization/infra/authserver/AuthorizationServerConfig.kt`
- `src/main/resources/db/migration/V2__oauth2_schema.sql`

Use the official Spring Authorization Server schema SQL for `oauth2_authorization`, `oauth2_registered_client`, `oauth2_authorization_consent` tables.

**Verification:**
```bash
./gradlew bootRun &
sleep 10

# OIDC discovery endpoint must exist
curl -s http://localhost:8080/.well-known/openid-configuration | jq .
# Expected: JSON with issuer, authorization_endpoint, token_endpoint, jwks_uri

# JWKS endpoint must return public key
curl -s http://localhost:8080/oauth2/jwks | jq .
# Expected: { "keys": [{ "kty": "RSA", "alg": "RS256", ... }] }
```

**Definition of Done:**
- [ ] `GET /.well-known/openid-configuration` returns valid OIDC discovery document
- [ ] `GET /oauth2/jwks` returns RS256 public key
- [ ] Flyway V2 migration applies cleanly — Spring Auth Server tables exist in DB

---

### Issue 19: OIDC token customizer + UserInfo endpoint

**Labels:** `sprint-5`, `authorization`

**Verification:**
```bash
# After completing authorization code flow, decode the issued JWT:
echo "<jwt-payload-base64>" | base64 -d | jq .
# Expected payload contains: sub, email, name, roles, iat, exp

# UserInfo endpoint
curl -s http://localhost:8080/userinfo \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq .
# Expected: { "sub": "...", "email": "...", "name": "...", "roles": [...] }
```

**Definition of Done:**
- [ ] Issued JWT contains `email`, `name`, `roles` claims
- [ ] `GET /userinfo` returns correct OIDC claims for the authenticated user

---

### Issue 20: OAuth2 client seeding

**Labels:** `sprint-5`, `authorization`

**File to create:** `src/main/resources/db/migration/V3__default_oauth2_clients.sql`

Seed two clients:
1. `iam-web` — Authorization Code + PKCE, redirect to `APP_BASE_URL/callback`
2. `iam-service` — Client Credentials only

**Verification:**
```bash
# Authorization Code flow
curl -s "http://localhost:8080/oauth2/authorize?response_type=code&client_id=iam-web&redirect_uri=http://localhost:3000/callback&code_challenge=<challenge>&code_challenge_method=S256"
# Expected: redirect to Google (or login page)

# Client Credentials flow
curl -s -X POST http://localhost:8080/oauth2/token \
  -u "iam-service:<secret>" \
  -d "grant_type=client_credentials" | jq .
# Expected: { "access_token": "...", "token_type": "Bearer", "expires_in": 900 }
```

**Definition of Done:**
- [ ] V3 migration applies cleanly
- [ ] Client Credentials flow returns a valid JWT
- [ ] Authorization Code flow redirects correctly (verify redirect URL in response)

---

## Sprint 6 — Audit Logs Bounded Context

---

### Issue 21: AuditLog aggregate + RecordAuditEventUseCase

**Labels:** `sprint-6`, `audit`

**Files to create:**
- `audit/domain/log/AuditEvent.kt`
- `audit/domain/log/AuditLog.kt`
- `audit/domain/log/AuditLogRepository.kt`
- `audit/usecase/RecordAuditEventUseCase.kt`
- `src/test/kotlin/.../audit/usecase/RecordAuditEventUseCaseTest.kt`

**`RecordAuditEventUseCaseTest.kt`:**
```kotlin
class RecordAuditEventUseCaseTest {
    private val repo = mockk<AuditLogRepository>()
    private val useCase = RecordAuditEventUseCase(repo)

    @Test fun `saves audit log with correct event type`() {
        every { repo.save(any()) } answers { firstArg() }
        useCase.execute(RecordAuditEventUseCase.Command(
            event = AuditEvent.AUTH_LOGIN_SUCCESS,
            userId = UUID.randomUUID(),
        ))
        verify { repo.save(match { it.eventType == AuditEvent.AUTH_LOGIN_SUCCESS.name }) }
    }

    @Test fun `saves log with null userId for failed login`() {
        every { repo.save(any()) } answers { firstArg() }
        useCase.execute(RecordAuditEventUseCase.Command(event = AuditEvent.AUTH_LOGIN_FAILURE))
        verify { repo.save(match { it.userId == null }) }
    }
}
```

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.audit.usecase.RecordAuditEventUseCaseTest"
# Expected: 2 tests pass

# After login event, check DB:
docker compose exec postgres psql -U iam -d iam \
  -c "SELECT event_type, user_id, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 5;"
# Expected: rows appear for each auth event
```

**Definition of Done:**
- [ ] Both `RecordAuditEventUseCaseTest` cases pass
- [ ] After login, `audit_logs` table contains `AUTH_LOGIN_SUCCESS` row
- [ ] `AuditLog` is append-only — no update or delete methods on repository

---

### Issue 22: Audit event integration — wire all BCs

**Labels:** `sprint-6`, `audit`

**Files to create:**
- `audit/domain/log/AuditDomainEvent.kt`
- `audit/infra/AuditEventListener.kt`

Update these use cases to publish `AuditDomainEvent`:
- `LoginWithGoogleUseCase` → `AUTH_LOGIN_SUCCESS`
- `AuthenticatePasskeyFinishUseCase` → `AUTH_LOGIN_SUCCESS`
- `RegisterPasskeyFinishUseCase` → `PASSKEY_REGISTERED`
- `DeletePasskeyUseCase` → `PASSKEY_DELETED`
- `CreateUserUseCase` → `USER_CREATED`
- `UpdateUserUseCase` → `USER_UPDATED`
- `ChangeUserStatusUseCase` → `USER_STATUS_CHANGED`
- `DeleteUserUseCase` → `USER_DELETED`
- `RefreshTokenUseCase` → `TOKEN_REFRESHED`
- `RevokeTokenUseCase` → `TOKEN_REVOKED`

**Verification:**
```bash
# Perform a Google login, then:
docker compose exec postgres psql -U iam -d iam \
  -c "SELECT event_type, user_id, ip_address FROM audit_logs ORDER BY created_at DESC LIMIT 10;"
# Expected: AUTH_LOGIN_SUCCESS row with correct user_id

# Perform a logout, then:
# Expected: TOKEN_REVOKED row appears

# Verify ALL event types are covered — count distinct event types after running through all flows
docker compose exec postgres psql -U iam -d iam \
  -c "SELECT DISTINCT event_type FROM audit_logs;"
```

**Definition of Done:**
- [ ] `AuditEventListenerTest`: listener calls `RecordAuditEventUseCase` when event published
- [ ] Manual flow: login → `AUTH_LOGIN_SUCCESS` row confirmed in DB
- [ ] Manual flow: logout → `TOKEN_REVOKED` row confirmed in DB
- [ ] Manual flow: register passkey → `PASSKEY_REGISTERED` row confirmed in DB

---

### Issue 23: QueryAuditLogsUseCase + Audit REST API

**Labels:** `sprint-6`, `audit`, `api`

**Files to create:**
- `audit/usecase/QueryAuditLogsUseCase.kt`
- `audit/api/AuditLogsController.kt`
- `audit/api/dto/AuditLogResponse.kt`

```
GET /api/v1/audit-logs?userId=&eventType=&from=&to=&page=0&size=20   (ADMIN)
GET /api/v1/audit-logs/{id}                                           (ADMIN)
```

Both return `ApiResponse<PageResponse<AuditLogResponse>>` and `ApiResponse<AuditLogResponse>` respectively.

**Verification:**
```bash
curl -s "http://localhost:8080/api/v1/audit-logs?page=0&size=10" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
# Expected:
# {
#   "success": true,
#   "data": {
#     "content": [...],
#     "page": 0, "size": 10, "totalElements": N, "totalPages": M
#   },
#   "error": null
# }

# Filter by event type
curl -s "http://localhost:8080/api/v1/audit-logs?eventType=AUTH_LOGIN_SUCCESS" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.data.content | length'
# Expected: count of login events

# Non-admin access must be rejected
curl -s "http://localhost:8080/api/v1/audit-logs" \
  -H "Authorization: Bearer $USER_TOKEN" | jq '.error.code'
# Expected: "FORBIDDEN"
```

**Definition of Done:**
- [ ] `AuditLogsControllerTest`: non-admin returns `FORBIDDEN`
- [ ] Pagination shape correct: `content`, `page`, `size`, `totalElements`, `totalPages`
- [ ] Filter by `eventType` returns only matching events
- [ ] No delete endpoint exists on `AuditLogsController`

---

## Sprint 7 — Hardening

---

### Issue 24: Rate limiting on sensitive endpoints

**Labels:** `sprint-7`, `security`

**Files to create:**
- `shared/ratelimit/RateLimitFilter.kt`
- `shared/config/RateLimitConfig.kt`

Rate limits:
- `POST /oauth2/token` → 10 requests/minute per IP
- `POST /api/v1/auth/passkey/authenticate/finish` → 5 requests/minute per IP

On limit exceeded: HTTP 429 + `ApiResponse.error("RATE_LIMIT_EXCEEDED", "Too many requests")`.

**Verification:**
```bash
# Hit token endpoint 11 times rapidly
for i in {1..11}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/oauth2/token \
    -d "grant_type=refresh_token&refresh_token=invalid"
done
# Expected: first 10 return 400 (bad token), 11th returns 429

# Verify error shape on 429
curl -s -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=refresh_token&refresh_token=invalid" | jq '.error.code'
# Expected: "RATE_LIMIT_EXCEEDED"
```

**Definition of Done:**
- [ ] 11th request to `/oauth2/token` within 1 minute returns HTTP 429
- [ ] 429 response body matches `ApiResponse` error shape
- [ ] `RateLimitFilterTest`: mock clock advances, verify limit resets after 1 minute

---

### Issue 25: CORS + Security headers

**Labels:** `sprint-7`, `security`

**Verification:**
```bash
# CORS preflight
curl -s -X OPTIONS http://localhost:8080/api/v1/users/me \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: GET" -v 2>&1 | grep -i "access-control"
# Expected: Access-Control-Allow-Origin: http://localhost:3000

# Security headers
curl -s -I http://localhost:8080/actuator/health | grep -i "x-content\|x-frame\|referrer"
# Expected:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# Referrer-Policy: strict-origin-when-cross-origin

# Origin NOT in allowed list must be rejected
curl -s -X OPTIONS http://localhost:8080/api/v1/users/me \
  -H "Origin: http://evil.com" -v 2>&1 | grep "access-control-allow-origin"
# Expected: empty (no CORS header → browser blocks it)
```

**Definition of Done:**
- [ ] Allowed origin receives correct CORS headers
- [ ] Disallowed origin receives no `Access-Control-Allow-Origin` header
- [ ] All three security headers present on every response

---

### Issue 26: SpringDoc OpenAPI configuration

**Labels:** `sprint-7`, `docs`

**Verification:**
```bash
curl -s http://localhost:8080/swagger-ui.html -w "%{http_code}" -o /dev/null
# Expected: 302 (redirect to swagger-ui/index.html)

curl -s http://localhost:8080/v3/api-docs | jq '.info.title'
# Expected: "IAM Service"

curl -s http://localhost:8080/v3/api-docs | jq '.components.securitySchemes'
# Expected: BearerAuth scheme present
```

**Definition of Done:**
- [ ] `/swagger-ui.html` loads without 404
- [ ] All `/api/v1/**` endpoints appear in the spec
- [ ] Bearer JWT security scheme documented
- [ ] `ApiResponse` wrapper visible in schema definitions

---

### Issue 27: Integration tests with Testcontainers

**Labels:** `sprint-7`, `testing`

**Files to create:**
- `src/test/kotlin/com/aibles/iam/BaseIntegrationTest.kt`
- `src/test/kotlin/com/aibles/iam/identity/UserCrudIntegrationTest.kt`
- `src/test/kotlin/com/aibles/iam/authorization/TokenRotationIntegrationTest.kt`

**`BaseIntegrationTest.kt`:**
```kotlin
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
abstract class BaseIntegrationTest {
    companion object {
        @Container @JvmStatic val postgres = PostgreSQLContainer<Nothing>("postgres:16-alpine")
        @Container @JvmStatic val redis = GenericContainer<Nothing>("redis:7-alpine").withExposedPorts(6379)

        @DynamicPropertySource @JvmStatic
        fun configure(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url", postgres::getJdbcUrl)
            registry.add("spring.datasource.username", postgres::getUsername)
            registry.add("spring.datasource.password", postgres::getPassword)
            registry.add("spring.data.redis.host", redis::getHost)
            registry.add("spring.data.redis.port") { redis.getMappedPort(6379) }
        }
    }
}
```

**`TokenRotationIntegrationTest`** must verify:
1. `IssueTokenUseCase` → access token is valid JWT with correct claims
2. `RefreshTokenUseCase` with valid token → new tokens issued
3. Old refresh token after rotation → `UnauthorizedException(TOKEN_INVALID)`
4. `RefreshTokenUseCase` with garbage token → `UnauthorizedException(TOKEN_INVALID)`

**Verification:**
```bash
./gradlew test --tests "com.aibles.iam.*IntegrationTest"
# Expected: BUILD SUCCESSFUL — all integration tests green
# (Testcontainers will pull images on first run — may take a few minutes)

# Full test suite
./gradlew test
# Expected: BUILD SUCCESSFUL — zero failures across all unit + integration tests
```

**Definition of Done:**
- [ ] `TokenRotationIntegrationTest`: all 4 scenarios pass against real Redis
- [ ] `UserCrudIntegrationTest`: create → read → update → disable → re-enable cycle passes against real DB
- [ ] `./gradlew test` → zero failures, total test count ≥ 40
- [ ] Coverage report: `./gradlew jacocoTestReport` — use cases ≥ 80% line coverage

---

## GitHub Issue Labels

| Label | Color | Description |
|-------|-------|-------------|
| `sprint-1` | `#0075ca` | Sprint 1: Foundation |
| `sprint-2` | `#0075ca` | Sprint 2: Identity BC |
| `sprint-3` | `#0075ca` | Sprint 3: Google OAuth2 + Tokens |
| `sprint-4` | `#0075ca` | Sprint 4: Passkey/WebAuthn |
| `sprint-5` | `#0075ca` | Sprint 5: OAuth2/OIDC Server |
| `sprint-6` | `#0075ca` | Sprint 6: Audit Logs |
| `sprint-7` | `#0075ca` | Sprint 7: Hardening |
| `setup` | `#e4e669` | Project setup |
| `identity` | `#d93f0b` | Identity BC |
| `authentication` | `#d93f0b` | Authentication BC |
| `authorization` | `#d93f0b` | Authorization BC |
| `audit` | `#d93f0b` | Audit BC |
| `shared` | `#bfd4f2` | Shared layer |
| `api` | `#bfd4f2` | REST API layer |
| `database` | `#bfd4f2` | DB migrations |
| `security` | `#e11d48` | Security hardening |
| `testing` | `#0e8a16` | Tests |
| `docs` | `#c2e0c6` | Documentation |
