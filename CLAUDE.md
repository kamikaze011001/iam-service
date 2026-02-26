# IAM Service — Claude Code Guide

## Project Overview

Single-tenant Identity & Access Management service.
**Kotlin 2.x + Spring Boot 3.4.x + Java 24 Virtual Threads.**
Provides Google OAuth2 login, Passkey (WebAuthn) authentication, OAuth2/OIDC SSO, and append-only audit logging.

---

## Environment Setup

### Java (SDKMAN)

The system default Java is **NOT Java 24**. SDKMAN is installed and Java 24 is managed through it.

**Java 24 is already installed:** `24.0.2-amzn` (Amazon Corretto)

To activate Java 24 for the current shell (run once per terminal session):
```bash
source ~/.sdkman/bin/sdkman-init.sh
sdk use java 24.0.2-amzn
```

To set as global default (already done — persists across sessions):
```bash
sdk default java 24.0.2-amzn
```

**Do NOT run `source ~/.sdkman/bin/sdkman-init.sh` before every command.** Run it once at the start of a terminal session, then all `./gradlew` commands work normally.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Kotlin 2.x |
| JVM | Java 24 (virtual threads — no synchronized pinning) |
| Framework | Spring Boot 3.4.x |
| Concurrency | Virtual Threads (`spring.threads.virtual.enabled=true`) |
| Security | Spring Security 6.x + Spring Authorization Server 1.4.x |
| WebAuthn | webauthn4j-spring-security |
| Database | PostgreSQL 16 — Spring Data JPA + Hibernate 6 |
| Cache / Sessions | Redis 7 — Spring Data Redis (Lettuce) |
| Migrations | Flyway |
| Build | Gradle 8 (Kotlin DSL) |
| Testing | JUnit 5, MockK, Testcontainers |
| API Docs | SpringDoc OpenAPI 3 |

---

## Architecture

### Style: Modular Monolith + Bounded Contexts + Use-Case Driven

- **Modular monolith** — single deployable JAR, divided internally by bounded context packages
- **Bounded contexts** — `identity`, `authentication`, `authorization`, `audit` each own their domain
- **Use-case driven** — no generic service layer; every operation is a dedicated `UseCase` class
- **JPA entity as domain** — `@Entity` lives in `domain/<aggregate>/`; use cases own all business logic
- **DTOs stay at API layer** — controllers map between DTOs ↔ domain; use cases never see HTTP types

### Package Structure

Each BC is divided into **aggregate-based sub-packages** under `domain/`.
Each aggregate sub-package owns its entity, repository interface, and related value objects.

```
com.aibles.iam/

├── identity/
│   ├── domain/
│   │   └── user/
│   │       ├── User.kt                        @Entity — state + simple invariants
│   │       ├── UserRepository.kt              interface : JpaRepository<User, UUID>
│   │       └── UserStatus.kt                  enum
│   ├── usecase/
│   │   ├── CreateUserUseCase.kt
│   │   ├── GetUserUseCase.kt
│   │   ├── UpdateUserUseCase.kt
│   │   ├── ChangeUserStatusUseCase.kt
│   │   └── DeleteUserUseCase.kt
│   └── api/
│       ├── UsersController.kt
│       └── dto/
│
├── authentication/
│   ├── domain/
│   │   └── passkey/
│   │       ├── PasskeyCredential.kt           @Entity
│   │       ├── PasskeyCredentialRepository.kt interface : JpaRepository
│   │       └── AuthChallenge.kt               value object
│   ├── usecase/
│   │   ├── LoginWithGoogleUseCase.kt
│   │   ├── RegisterPasskeyStartUseCase.kt
│   │   ├── RegisterPasskeyFinishUseCase.kt
│   │   ├── AuthenticatePasskeyStartUseCase.kt
│   │   ├── AuthenticatePasskeyFinishUseCase.kt
│   │   └── DeletePasskeyUseCase.kt
│   ├── infra/
│   │   └── GoogleIdTokenVerifier.kt           external call — lives in infra
│   └── api/
│       ├── PasskeyController.kt
│       ├── AuthController.kt
│       └── dto/
│
├── authorization/
│   ├── domain/
│   │   └── token/
│   │       ├── RefreshToken.kt                value object
│   │       └── TokenStore.kt                  interface (Redis-backed)
│   ├── usecase/
│   │   ├── IssueTokenUseCase.kt
│   │   ├── RefreshTokenUseCase.kt
│   │   └── RevokeTokenUseCase.kt
│   └── infra/
│       ├── RedisTokenStore.kt                 implements TokenStore
│       ├── JwtService.kt                      RS256 sign/verify
│       └── authserver/                        Spring Authorization Server customizations
│
├── audit/
│   ├── domain/
│   │   └── log/
│   │       ├── AuditLog.kt                    @Entity
│   │       ├── AuditLogRepository.kt          interface : JpaRepository
│   │       └── AuditEvent.kt                  enum of all event types
│   ├── usecase/
│   │   ├── RecordAuditEventUseCase.kt
│   │   └── QueryAuditLogsUseCase.kt
│   └── api/
│       ├── AuditLogsController.kt
│       └── dto/
│
└── shared/
    ├── config/                                SecurityConfig, RedisConfig, VirtualThreadsConfig
    ├── error/
    │   ├── ErrorCode.kt                       enum — single source of truth for all error codes
    │   ├── BaseException.kt                   abstract; carries ErrorCode + message
    │   ├── AppExceptions.kt                   concrete typed exceptions
    │   └── GlobalExceptionHandler.kt          single @ExceptionHandler(BaseException::class)
    ├── response/
    │   └── ApiResponse.kt                     consistent response wrapper for all endpoints
    └── pagination/
        └── PageResponse.kt                    paginated response wrapper
```

### Use Case Convention

```kotlin
@Component
class CreateUserUseCase(private val userRepository: UserRepository) {
    data class Command(val email: String, val displayName: String?, val googleSub: String?)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        if (userRepository.existsByEmail(command.email))
            throw ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)
        val user = User.create(command.email, command.displayName, command.googleSub)
        return Result(userRepository.save(user))
    }
}
```

- Single `execute(command)` method with nested `Command` + `Result`
- `@Component` — Spring-managed, testable with MockK
- Throws typed exceptions from `AppExceptions.kt` with `ErrorCode`
- May call other use cases; never calls controllers

### Error Handling

**ErrorCode enum** is the single source of truth — each code carries its own HTTP status:

```kotlin
enum class ErrorCode(val httpStatus: HttpStatus) {
    // Generic
    BAD_REQUEST(HttpStatus.BAD_REQUEST),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED),
    FORBIDDEN(HttpStatus.FORBIDDEN),
    CONFLICT(HttpStatus.CONFLICT),
    VALIDATION_ERROR(HttpStatus.UNPROCESSABLE_ENTITY),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR),

    // Identity
    USER_NOT_FOUND(HttpStatus.NOT_FOUND),
    USER_EMAIL_CONFLICT(HttpStatus.CONFLICT),
    USER_DISABLED(HttpStatus.FORBIDDEN),

    // Authentication
    GOOGLE_TOKEN_INVALID(HttpStatus.UNAUTHORIZED),
    PASSKEY_NOT_FOUND(HttpStatus.NOT_FOUND),
    PASSKEY_COUNTER_INVALID(HttpStatus.UNAUTHORIZED),
    PASSKEY_CHALLENGE_EXPIRED(HttpStatus.BAD_REQUEST),
    PASSKEY_ATTESTATION_FAILED(HttpStatus.BAD_REQUEST),

    // Authorization
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED),
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED),
    TOKEN_REVOKED(HttpStatus.UNAUTHORIZED),
}
```

**Exception hierarchy:**

```kotlin
abstract class BaseException(
    val errorCode: ErrorCode,
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause) {
    val httpStatus: HttpStatus get() = errorCode.httpStatus
}

class NotFoundException(message: String, errorCode: ErrorCode)     : BaseException(errorCode, message)
class ConflictException(message: String, errorCode: ErrorCode)      : BaseException(errorCode, message)
class UnauthorizedException(message: String, errorCode: ErrorCode)  : BaseException(errorCode, message)
class ForbiddenException(message: String, errorCode: ErrorCode)     : BaseException(errorCode, message)
class BadRequestException(message: String, errorCode: ErrorCode)    : BaseException(errorCode, message)
class ValidationException(message: String, val fields: Map<String, String> = emptyMap())
    : BaseException(ErrorCode.VALIDATION_ERROR, message)
```

**GlobalExceptionHandler — 3 cases only:**

```kotlin
@RestControllerAdvice
class GlobalExceptionHandler {
    @ExceptionHandler(BaseException::class)
    fun handle(e: BaseException) =
        ResponseEntity.status(e.httpStatus).body(ApiResponse.error(e.errorCode.name, e.message!!))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(e: MethodArgumentNotValidException) = ...

    @ExceptionHandler(Exception::class)
    fun handleUnexpected(e: Exception) =
        ResponseEntity.internalServerError().body(ApiResponse.error("INTERNAL_ERROR", "Unexpected error"))
}
```

### Response Format

All endpoints return `ApiResponse<T>` — a consistent wrapper:

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
{ "success": false, "data": null, "error": { "code": "USER_NOT_FOUND", "message": "..." }, "timestamp": "..." }
```

Paginated responses wrap `PageResponse<T>` inside `data`:

```kotlin
data class PageResponse<T>(
    val content: List<T>,
    val page: Int,
    val size: Int,
    val totalElements: Long,
    val totalPages: Int,
)
// e.g. ApiResponse.ok(PageResponse(content = users, page = 0, size = 20, ...))
```

### Cross-BC Communication

- **Synchronous**: use case injects another use case directly
- **Audit**: Spring `ApplicationEventPublisher` — other BCs publish domain events; audit BC listens
- **No circular dependencies** between bounded contexts

---

## Development Workflow

### Sprint-Based with GitHub Issues

Complete **all issues in a sprint before starting the next sprint**.

| Sprint | Theme |
|--------|-------|
| 1 | Foundation: scaffold, Docker Compose, Flyway, virtual threads, shared error/response |
| 2 | Identity BC: User aggregate, CRUD use cases, Users API |
| 3 | Google OAuth2 + Token Management: login, JWT, refresh rotation |
| 4 | Passkey / WebAuthn: registration + authentication flows |
| 5 | OAuth2/OIDC Authorization Server: SSO, auth code, client credentials |
| 6 | Audit Logs BC: recording + query API |
| 7 | Hardening: rate limiting, CORS, OpenAPI, integration tests |

### Per-Issue Workflow

> ⚠️ **CRITICAL — MUST follow this exact sequence for EVERY issue, no exceptions:**

```bash
# 1. Start from main (or latest base branch)
git checkout main

# 2. Create a feature branch for this specific issue
git checkout -b feature/<issue-number>-<short-description>

# 3. Implement with TDD: failing test → implement → pass
# ... write code ...

# 4. Commit
git commit -m "feat: <description> (Closes #<issue-number>)"

# 5. Push branch to remote
git push -u origin feature/<issue-number>-<short-description>

# 6. Create PR linking the issue
gh pr create \
  --title "<issue title>" \
  --body "Closes #<issue-number>" \
  --base main

# 7. Merge the PR
gh pr merge <pr-number> --squash --delete-branch

# 8. Pull latest main
git checkout main
git pull origin main

# 9. Only then start the next issue (repeat from step 1)
```

**Rules:**
- NEVER start a new issue without merging the previous one first
- ALWAYS create a PR even for small changes — the PR is the paper trail
- ALWAYS use `Closes #<N>` in the PR body to auto-close the GitHub issue
- ALWAYS delete the branch after merge (`--delete-branch`)

### Running Locally

```bash
docker compose up -d          # start PostgreSQL + Redis
./gradlew bootRun             # start service on :8080
./gradlew test                # unit tests
./gradlew test jacocoTestReport
```

---

## Security Rules (CRITICAL)

### File Access Restrictions

- NEVER read files in: `~/.ssh/`, `~/.aws/`, `~/.config/`, `~/.env`
- NEVER read `.env` files directly — use `.env.example` for reference
- NEVER traverse parent directories (`../`) to access files outside project

### Command Restrictions

- NEVER run `rm -rf` without explicit user confirmation
- NEVER run `git push` without showing diff first
- NEVER run `curl`/`wget` with credentials in URL
- NEVER run commands with `--force` flag without confirmation

### Code Generation Rules

- NEVER hardcode API keys, tokens, or secrets
- ALWAYS use environment variables — reference `.env.example` for variable names
- NEVER include real credential values in comments or documentation

### Git Rules

- NEVER commit `.env` files
- ALWAYS verify `.gitignore` includes secret files before committing
- NEVER force push to `main`/`master` branch
