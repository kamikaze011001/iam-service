# IAM Service — Architecture Design

> **Date:** 2026-02-27 | **Status:** Approved

---

## 1. Purpose

Single-tenant IAM service providing:
- Authentication via Google OAuth2 and Passkey (WebAuthn/FIDO2)
- OAuth2/OIDC Authorization Server for SSO across internal services
- JWT access tokens (RS256) with refresh token rotation
- User identity management with role-based access
- Tamper-evident, append-only audit logs

---

## 2. Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Kotlin 2.x |
| JVM | Java 24 — virtual threads with no synchronized pinning |
| Framework | Spring Boot 3.4.x |
| Concurrency | Virtual Threads (`spring.threads.virtual.enabled=true`) |
| Security | Spring Security 6.x + Spring Authorization Server 1.4.x |
| WebAuthn | webauthn4j-spring-security |
| Database | PostgreSQL 16 — Spring Data JPA + Hibernate 6 |
| Cache | Redis 7 — Spring Data Redis (Lettuce) |
| Migrations | Flyway |
| Build | Gradle 8 (Kotlin DSL) |
| Testing | JUnit 5, MockK, Testcontainers |

---

## 3. Architecture

### 3.1 Style

**Modular monolith** — single JAR, divided by bounded context packages.
**Use-case driven** — no generic service layer; one class per operation.
**JPA entity as domain** — `@Entity` in `domain/<aggregate>/`; use cases own all logic.

### 3.2 Bounded Contexts

| BC | Responsibility |
|----|---------------|
| `identity` | Who is the user? User entity, CRUD, roles |
| `authentication` | How does the user prove identity? Google OAuth2, Passkey/WebAuthn |
| `authorization` | Token issuance and SSO — JWT, refresh rotation, Spring Auth Server |
| `audit` | What happened? Append-only audit log |

### 3.3 Package Layout

Each BC uses **aggregate-based sub-packages** under `domain/`. The aggregate sub-package owns its entity, repository interface, and related value objects.

```
com.aibles.iam/
├── identity/
│   ├── domain/user/           User @Entity, UserRepository, UserStatus
│   ├── usecase/               CreateUserUseCase, GetUserUseCase, ...
│   └── api/                   UsersController + dto/
│
├── authentication/
│   ├── domain/passkey/        PasskeyCredential @Entity, PasskeyCredentialRepository, AuthChallenge
│   ├── usecase/               LoginWithGoogleUseCase, RegisterPasskeyStartUseCase, ...
│   ├── infra/                 GoogleIdTokenVerifier
│   └── api/                   PasskeyController, AuthController + dto/
│
├── authorization/
│   ├── domain/token/          RefreshToken value object, TokenStore interface
│   ├── usecase/               IssueTokenUseCase, RefreshTokenUseCase, RevokeTokenUseCase
│   └── infra/                 RedisTokenStore, JwtService, authserver/
│
├── audit/
│   ├── domain/log/            AuditLog @Entity, AuditLogRepository, AuditEvent enum
│   ├── usecase/               RecordAuditEventUseCase, QueryAuditLogsUseCase
│   └── api/                   AuditLogsController + dto/
│
└── shared/
    ├── config/                SecurityConfig, RedisConfig
    ├── error/                 ErrorCode, BaseException, AppExceptions, GlobalExceptionHandler
    ├── response/              ApiResponse, ErrorDetail
    └── pagination/            PageResponse
```

### 3.4 Use Case Pattern

```kotlin
@Component
class CreateUserUseCase(private val userRepository: UserRepository) {
    data class Command(val email: String, val displayName: String?, val googleSub: String?)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        if (userRepository.existsByEmail(command.email))
            throw ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)
        return Result(userRepository.save(User.create(command.email, command.displayName, command.googleSub)))
    }
}
```

### 3.5 Domain Object Pattern

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
            require(email.contains("@")) { "Invalid email" }
            return User(email = email.lowercase().trim(), displayName = displayName, googleSub = googleSub)
        }
    }

    fun updateProfile(displayName: String) { this.displayName = displayName.trim(); updatedAt = Instant.now() }
    fun disable() { status = UserStatus.DISABLED; updatedAt = Instant.now() }
    fun enable()  { status = UserStatus.ACTIVE;   updatedAt = Instant.now() }
    fun recordLogin() { lastLoginAt = Instant.now(); updatedAt = Instant.now() }
    fun isActive() = status == UserStatus.ACTIVE
}
```

---

## 4. Error Handling

### 4.1 ErrorCode Enum

Single source of truth. Each code carries its own HTTP status — no mapping logic needed elsewhere.

```kotlin
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

### 4.2 Exception Hierarchy

```
BaseException (abstract)
├── NotFoundException(message, errorCode)
├── ConflictException(message, errorCode)
├── UnauthorizedException(message, errorCode)
├── ForbiddenException(message, errorCode)
├── BadRequestException(message, errorCode)
└── ValidationException(message, fields: Map<String,String>)   ← always VALIDATION_ERROR code
```

`BaseException` derives `httpStatus` from `errorCode.httpStatus` — no duplication.

### 4.3 GlobalExceptionHandler

Three cases only:

```kotlin
@ExceptionHandler(BaseException::class)              // all our exceptions
@ExceptionHandler(MethodArgumentNotValidException::class)   // @Valid failures
@ExceptionHandler(Exception::class)                  // unexpected — never expose stack trace
```

---

## 5. Response Format

All endpoints return `ApiResponse<T>`:

```kotlin
data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val error: ErrorDetail? = null,
    val timestamp: Instant = Instant.now(),
) {
    companion object {
        fun <T> ok(data: T) = ApiResponse(success = true, data = data)
        fun error(code: String, message: String) =
            ApiResponse<Nothing>(success = false, error = ErrorDetail(code, message))
    }
}

data class ErrorDetail(val code: String, val message: String)
```

```json
// success
{ "success": true,  "data": { "id": "...", "email": "..." }, "error": null,  "timestamp": "..." }

// error
{ "success": false, "data": null, "error": { "code": "USER_NOT_FOUND", "message": "User not found" }, "timestamp": "..." }

// paginated success
{ "success": true,  "data": { "content": [...], "page": 0, "size": 20, "totalElements": 42, "totalPages": 3 }, "error": null, "timestamp": "..." }
```

---

## 6. Authentication Flows

### 6.1 Google OAuth2 Login

```
Browser → GET /oauth2/authorize → Google
Google  → GET /login/oauth2/code/google?code=...
Spring Security exchanges code → id_token
LoginWithGoogleUseCase:
  1. GoogleIdTokenVerifier.verify(idToken) → googleSub, email, name
  2. FindOrCreateUserByGoogleUseCase → upsert in identity BC
  3. IssueTokenUseCase → RS256 JWT (15min) + refresh token UUID in Redis (7d)
  4. ApplicationEventPublisher.publish(AuditDomainEvent(AUTH_LOGIN_SUCCESS))
  5. return { accessToken, refreshToken }
```

### 6.2 Passkey Registration

```
POST /api/v1/auth/passkey/register/start
  → generate WebAuthn4J PublicKeyCredentialCreationOptions
  → store challenge in Redis (TTL 5min, key: wc:{sessionId})
  → return options JSON

POST /api/v1/auth/passkey/register/finish
  → verify WebAuthn4J attestation + challenge from Redis
  → save PasskeyCredential (CBOR public key, sign counter, AAGUID)
  → publish PASSKEY_REGISTERED audit event
```

### 6.3 Passkey Authentication

```
POST /api/v1/auth/passkey/authenticate/start
  → generate challenge, store in Redis

POST /api/v1/auth/passkey/authenticate/finish
  → verify assertion signature
  → validate sign counter > stored counter (replay attack prevention)
  → increment + save sign counter
  → IssueTokenUseCase → JWT + refresh token
  → publish AUTH_LOGIN_SUCCESS audit event
```

### 6.4 Refresh Token Rotation

```
POST /oauth2/token (grant_type=refresh_token)
  → validate token in Redis (must exist, not expired)
  → DELETE old token (one-time use)
  → issue new JWT + new refresh token
  → store new refresh token in Redis
  → publish TOKEN_REFRESHED audit event
```

---

## 7. Token Design

| Token | Algorithm | TTL | Storage |
|-------|-----------|-----|---------|
| Access Token (JWT) | RS256 | 15 min | Client memory only |
| Refresh Token | UUID | 7 days | Redis: `rt:{uuid}` → userId |
| Authorization Code | UUID | 5 min | Redis: `ac:{code}` → clientId+userId |
| WebAuthn Challenge | UUID | 5 min | Redis: `wc:{sessionId}` → challenge |

JWKS at `/oauth2/jwks` — downstream services verify JWTs locally.

---

## 8. Data Model

### users
```sql
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
```

### passkey_credentials
```sql
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
```

### audit_logs
```sql
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

---

## 9. API Surface

```
# Spring Authorization Server
GET  /oauth2/authorize
POST /oauth2/token
POST /oauth2/revoke
GET  /oauth2/jwks
GET  /.well-known/openid-configuration
GET  /userinfo

# Google OAuth2 callback
GET  /login/oauth2/code/google

# Passkey
POST   /api/v1/auth/passkey/register/start
POST   /api/v1/auth/passkey/register/finish
POST   /api/v1/auth/passkey/authenticate/start
POST   /api/v1/auth/passkey/authenticate/finish
GET    /api/v1/auth/passkey/credentials
DELETE /api/v1/auth/passkey/credentials/{id}

# Session
POST /api/v1/auth/logout

# Users
GET    /api/v1/users/me
PATCH  /api/v1/users/me
GET    /api/v1/users                    (ADMIN)
GET    /api/v1/users/{id}               (ADMIN)
PATCH  /api/v1/users/{id}/status        (ADMIN)
DELETE /api/v1/users/{id}               (ADMIN, soft-delete)

# Audit
GET  /api/v1/audit-logs                 (ADMIN, filterable: userId, eventType, from, to)
GET  /api/v1/audit-logs/{id}            (ADMIN)

# Health
GET  /actuator/health
```

---

## 10. Audit Events

```kotlin
enum class AuditEvent {
    AUTH_LOGIN_SUCCESS, AUTH_LOGIN_FAILURE, AUTH_LOGOUT,
    TOKEN_ISSUED, TOKEN_REFRESHED, TOKEN_REVOKED,
    PASSKEY_REGISTERED, PASSKEY_DELETED,
    USER_CREATED, USER_UPDATED, USER_STATUS_CHANGED, USER_DELETED,
    OAUTH2_CODE_ISSUED, OAUTH2_TOKEN_ISSUED,
}
```

---

## 11. Security

| Concern | Mitigation |
|---------|-----------|
| JWT algorithm confusion | Only RS256 accepted; `alg` header validated |
| Refresh token replay | One-time use rotation — deleted on consumption |
| Passkey replay | Sign counter strictly increasing; rejected if ≤ stored |
| Thread pinning | Java 24 — `synchronized` parks virtual thread, not OS thread |
| Rate limiting | Bucket4j on `/oauth2/token` and passkey auth endpoints |
| Secret leakage | All credentials via env vars; `.env` never committed |
| Error leakage | Unexpected exceptions return generic `INTERNAL_ERROR` — no stack traces |

---

## 12. Sprint Map

| Sprint | Focus |
|--------|-------|
| 1 | Foundation: scaffold, Docker Compose, Flyway, shared error/response layer |
| 2 | Identity BC: User aggregate, CRUD use cases, Users API |
| 3 | Google OAuth2 + Token Management |
| 4 | Passkey/WebAuthn: registration + authentication |
| 5 | OAuth2/OIDC Server: SSO, Authorization Code, Client Credentials |
| 6 | Audit Logs BC: recording + query API |
| 7 | Hardening: rate limiting, CORS, OpenAPI, integration tests |
