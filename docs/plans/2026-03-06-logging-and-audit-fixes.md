# Logging & Audit Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add structured logging across all flows, fix REGISTRATION_COMPLETED audit event missing user data, and capture ip_address/user_agent on all audit events.

**Architecture:**
- MDC filter sets `requestId` + `clientIp` + `userAgent` on every request for log correlation
- AOP aspect auto-logs all use case `execute()` calls at DEBUG level — zero per-class boilerplate
- A shared `HttpContextExtractor` utility (reads `RequestContextHolder`) provides IP/UA to use cases and controllers without polluting method signatures with `HttpServletRequest`
- `FinishRegistrationUseCase.Result` gains `userId` + `email` so `REGISTRATION_COMPLETED` can be fully populated

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, SLF4J + Logback, Spring AOP (`spring-boot-starter-aop`), MDC, `RequestContextHolder`

---

## Problem Map

| # | Problem | Root Cause | Fix |
|---|---------|-----------|-----|
| 1 | No logs anywhere | No logback config, no loggers in use cases, GlobalExceptionHandler swallows silently | Tasks 1–4 |
| 2 | REGISTRATION_COMPLETED has no user data | `FinishRegistrationUseCase.Result` exposes only tokens; event published with empty fields | Task 5 |
| 3 | ip_address / user_agent always null | No code extracts IP/UA from request before publishing audit events | Tasks 6–7 |
| 4 | (Bonus) PASSKEY_REGISTERED / PASSKEY_AUTHENTICATED / PASSKEY_DELETED never published | Controllers don't publish these events at all | Task 8 |

---

## Task 1: Logback Configuration

**Goal:** Structured logs with readable format in dev, JSON-ready in prod. No changes to any Kotlin code yet.

**Files:**
- Create: `src/main/resources/logback-spring.xml`
- Modify: `src/main/resources/application.yml`

**Step 1: Create logback-spring.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>

    <!-- Dev profile: human-readable pattern with color -->
    <springProfile name="!prod">
        <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
            <encoder>
                <pattern>%d{HH:mm:ss.SSS} %highlight(%-5level) [%cyan(%X{requestId:-no-req})] [%yellow(%X{clientIp:-?})] %logger{36} - %msg%n</pattern>
            </encoder>
        </appender>
        <root level="INFO">
            <appender-ref ref="CONSOLE"/>
        </root>
        <logger name="com.aibles.iam" level="DEBUG"/>
    </springProfile>

    <!-- Prod profile: plain pattern (pipe to external JSON formatter or use logstash-logback-encoder later) -->
    <springProfile name="prod">
        <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
            <encoder>
                <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} %-5level [%X{requestId:-no-req}] [%X{clientIp:-?}] %logger{36} - %msg%n</pattern>
            </encoder>
        </appender>
        <root level="INFO">
            <appender-ref ref="CONSOLE"/>
        </root>
        <logger name="com.aibles.iam" level="INFO"/>
    </springProfile>

    <!-- Always suppress noisy Spring/Hibernate internals -->
    <logger name="org.hibernate.SQL" level="WARN"/>
    <logger name="org.springframework.security" level="WARN"/>
    <logger name="org.springframework.web" level="WARN"/>

</configuration>
```

**Step 2: Add log level config to application.yml**

Add under the top-level of `application.yml`:
```yaml
logging:
  level:
    root: INFO
    com.aibles.iam: DEBUG
```

**Step 3: Verify — start the app and confirm log output appears**

```bash
./gradlew bootRun
# Should see formatted log lines with HH:mm:ss pattern
```

Expected: Spring startup logs with the new pattern. No compilation needed.

**Step 4: Commit**

```bash
git add src/main/resources/logback-spring.xml src/main/resources/application.yml
git commit -m "chore: add logback-spring.xml structured logging config"
```

---

## Task 2: MDC Request Filter

**Goal:** Every request gets a unique `requestId` UUID in MDC, plus `clientIp` and `userAgent`. All subsequent log lines in that request thread automatically include these values via `%X{requestId}` in the pattern.

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/logging/MdcRequestFilter.kt`

**Step 1: Write the failing test**

Create: `src/test/kotlin/com/aibles/iam/shared/logging/MdcRequestFilterTest.kt`

```kotlin
package com.aibles.iam.shared.logging

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.junit.jupiter.api.Test
import org.slf4j.MDC

class MdcRequestFilterTest {

    private val filter = MdcRequestFilter()
    private val request = mockk<HttpServletRequest>(relaxed = true)
    private val response = mockk<HttpServletResponse>(relaxed = true)
    private val chain = mockk<FilterChain>(relaxed = true)

    @Test
    fun `sets requestId in MDC and clears after request`() {
        every { request.remoteAddr } returns "127.0.0.1"
        every { request.getHeader("X-Forwarded-For") } returns null
        every { request.getHeader("User-Agent") } returns "TestAgent/1.0"

        filter.doFilterInternal(request, response, chain)

        // MDC must be cleared after request completes
        assert(MDC.get("requestId") == null)
        verify { chain.doFilter(request, response) }
    }

    @Test
    fun `uses X-Forwarded-For IP when present`() {
        every { request.remoteAddr } returns "10.0.0.1"
        every { request.getHeader("X-Forwarded-For") } returns "203.0.113.5, 10.0.0.1"
        every { request.getHeader("User-Agent") } returns null

        var capturedIp: String? = null
        every { chain.doFilter(any(), any()) } answers {
            capturedIp = MDC.get("clientIp")
        }

        filter.doFilterInternal(request, response, chain)

        assert(capturedIp == "203.0.113.5") { "Expected first XFF IP, got $capturedIp" }
    }
}
```

**Step 2: Run test to verify it fails**

```bash
./gradlew test --tests "com.aibles.iam.shared.logging.MdcRequestFilterTest"
```

Expected: FAIL — `MdcRequestFilter` doesn't exist yet.

**Step 3: Implement MdcRequestFilter**

```kotlin
package com.aibles.iam.shared.logging

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.core.annotation.Order
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.util.UUID

@Component
@Order(1)  // Run before other filters so MDC is available everywhere
class MdcRequestFilter : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            MDC.put("requestId", UUID.randomUUID().toString().take(8))
            MDC.put("clientIp", resolveClientIp(request))
            MDC.put("userAgent", request.getHeader("User-Agent") ?: "unknown")
            filterChain.doFilter(request, response)
        } finally {
            MDC.clear()  // CRITICAL: always clear MDC — virtual threads are reused
        }
    }

    internal fun resolveClientIp(request: HttpServletRequest): String {
        val xff = request.getHeader("X-Forwarded-For")
        if (!xff.isNullOrBlank()) {
            return xff.split(",").first().trim()
        }
        return request.remoteAddr
    }
}
```

**Step 4: Run test to verify it passes**

```bash
./gradlew test --tests "com.aibles.iam.shared.logging.MdcRequestFilterTest"
```

Expected: PASS

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/logging/MdcRequestFilter.kt \
        src/test/kotlin/com/aibles/iam/shared/logging/MdcRequestFilterTest.kt
git commit -m "feat(logging): MDC request filter — requestId, clientIp, userAgent per request"
```

---

## Task 3: AOP Use Case Logging Aspect

**Goal:** Every `UseCase.execute()` call is automatically logged at DEBUG (entry/exit/duration) and ERROR (exceptions) — without touching any of the 25 use case classes.

**Files:**
- Modify: `build.gradle.kts` — add `spring-boot-starter-aop`
- Create: `src/main/kotlin/com/aibles/iam/shared/logging/UseCaseLoggingAspect.kt`

**Step 1: Add AOP dependency**

In `build.gradle.kts`, inside `dependencies { }`, add:
```kotlin
implementation("org.springframework.boot:spring-boot-starter-aop")
```

**Step 2: Write the failing test**

Create: `src/test/kotlin/com/aibles/iam/shared/logging/UseCaseLoggingAspectTest.kt`

```kotlin
package com.aibles.iam.shared.logging

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.EnableAspectJAutoProxy
import org.springframework.stereotype.Component

@SpringBootTest(classes = [UseCaseLoggingAspectTest.TestConfig::class, UseCaseLoggingAspect::class])
class UseCaseLoggingAspectTest {

    @Configuration
    @EnableAspectJAutoProxy
    class TestConfig {
        @Bean
        fun testUseCase() = TestUseCase()
    }

    @Component
    class TestUseCase {
        fun execute(command: String): String = "result-$command"
    }

    @Autowired
    lateinit var testUseCase: TestUseCase

    @Test
    fun `execute completes without throwing when aspect is wired`() {
        // If aspect wiring is broken, Spring context fails to load
        val result = testUseCase.execute("input")
        assert(result == "result-input")
    }
}
```

**Step 3: Run test to verify it fails**

```bash
./gradlew test --tests "com.aibles.iam.shared.logging.UseCaseLoggingAspectTest"
```

Expected: FAIL — `UseCaseLoggingAspect` doesn't exist.

**Step 4: Implement UseCaseLoggingAspect**

```kotlin
package com.aibles.iam.shared.logging

import org.aspectj.lang.ProceedingJoinPoint
import org.aspectj.lang.annotation.Around
import org.aspectj.lang.annotation.Aspect
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Component

@Aspect
@Component
class UseCaseLoggingAspect {

    @Around("execution(* com.aibles.iam..usecase.*.execute(..))")
    fun logUseCaseExecution(pjp: ProceedingJoinPoint): Any? {
        val useCaseName = pjp.target.javaClass.simpleName
        val logger = LoggerFactory.getLogger(pjp.target.javaClass)

        logger.debug("{} starting", useCaseName)
        val start = System.currentTimeMillis()
        return try {
            val result = pjp.proceed()
            val elapsed = System.currentTimeMillis() - start
            logger.debug("{} completed in {}ms", useCaseName, elapsed)
            result
        } catch (e: Exception) {
            val elapsed = System.currentTimeMillis() - start
            // WARN for expected domain failures (BaseException), ERROR for unexpected
            if (e is com.aibles.iam.shared.error.BaseException) {
                logger.warn("{} failed after {}ms: [{}] {}", useCaseName, elapsed, e.errorCode, e.message)
            } else {
                logger.error("{} threw unexpected exception after {}ms", useCaseName, elapsed, e)
            }
            throw e
        }
    }
}
```

**Step 5: Run test to verify it passes**

```bash
./gradlew test --tests "com.aibles.iam.shared.logging.UseCaseLoggingAspectTest"
```

Expected: PASS

**Step 6: Run full test suite to make sure nothing broke**

```bash
./gradlew test
```

Expected: All tests pass.

**Step 7: Commit**

```bash
git add build.gradle.kts \
        src/main/kotlin/com/aibles/iam/shared/logging/UseCaseLoggingAspect.kt \
        src/test/kotlin/com/aibles/iam/shared/logging/UseCaseLoggingAspectTest.kt
git commit -m "feat(logging): AOP aspect — auto-log all use case execute() at DEBUG"
```

---

## Task 4: GlobalExceptionHandler Logging

**Goal:** No more silent swallowing of exceptions. `BaseException` (expected) logs at WARN, unknown `Exception` logs at ERROR with full stack trace.

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandler.kt`

**Step 1: Read the current file first**

File: `src/main/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandler.kt` (already read above — 30 lines, no logger)

**Step 2: Write the failing test**

Create: `src/test/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandlerTest.kt`

```kotlin
package com.aibles.iam.shared.error

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@WebMvcTest(GlobalExceptionHandlerTest.ThrowingController::class)
@Import(GlobalExceptionHandler::class)
class GlobalExceptionHandlerTest {

    @RestController
    class ThrowingController {
        @GetMapping("/test/base-exception")
        fun throwBase(): String = throw NotFoundException("not found", ErrorCode.USER_NOT_FOUND)

        @GetMapping("/test/unexpected")
        fun throwUnexpected(): String = throw RuntimeException("boom")
    }

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    @WithMockUser
    fun `BaseException returns correct status and error body`() {
        mockMvc.get("/test/base-exception") {
            accept(MediaType.APPLICATION_JSON)
        }.andExpect {
            status { isNotFound() }
            jsonPath("$.success") { value(false) }
            jsonPath("$.error.code") { value("USER_NOT_FOUND") }
        }
    }

    @Test
    @WithMockUser
    fun `unexpected Exception returns 500`() {
        mockMvc.get("/test/unexpected") {
            accept(MediaType.APPLICATION_JSON)
        }.andExpect {
            status { isInternalServerError() }
            jsonPath("$.error.code") { value("INTERNAL_ERROR") }
        }
    }
}
```

**Step 3: Run test to verify it passes already (behavior unchanged)**

```bash
./gradlew test --tests "com.aibles.iam.shared.error.GlobalExceptionHandlerTest"
```

Expected: PASS — we're verifying behavior before adding logging.

**Step 4: Add logger to GlobalExceptionHandler**

Edit `src/main/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandler.kt`:

```kotlin
package com.aibles.iam.shared.error

import com.aibles.iam.shared.response.ApiResponse
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {

    private val logger = LoggerFactory.getLogger(javaClass)

    @ExceptionHandler(BaseException::class)
    fun handleBase(e: BaseException): ResponseEntity<ApiResponse<Nothing>> {
        logger.warn("Domain exception [{}]: {}", e.errorCode, e.message)
        return ResponseEntity.status(e.httpStatus)
            .body(ApiResponse.error(e.errorCode.name, e.message ?: "Error"))
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(e: MethodArgumentNotValidException): ResponseEntity<ApiResponse<Nothing>> {
        val msg = e.bindingResult.fieldErrors.joinToString("; ") {
            "${it.field}: ${it.defaultMessage}"
        }
        logger.warn("Validation failed: {}", msg)
        return ResponseEntity.status(422)
            .body(ApiResponse.error(ErrorCode.VALIDATION_ERROR.name, msg))
    }

    @ExceptionHandler(Exception::class)
    fun handleUnexpected(e: Exception): ResponseEntity<ApiResponse<Nothing>> {
        logger.error("Unhandled exception", e)  // stack trace logged here
        return ResponseEntity.internalServerError()
            .body(ApiResponse.error(ErrorCode.INTERNAL_ERROR.name, "Unexpected error"))
    }
}
```

**Step 5: Run test again to verify behavior still correct**

```bash
./gradlew test --tests "com.aibles.iam.shared.error.GlobalExceptionHandlerTest"
```

Expected: PASS

**Step 6: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandler.kt \
        src/test/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandlerTest.kt
git commit -m "feat(logging): GlobalExceptionHandler — WARN for domain errors, ERROR+stack for unexpected"
```

---

## Task 5: Fix REGISTRATION_COMPLETED Audit Event (Problem 2)

**Goal:** `REGISTRATION_COMPLETED` in audit_logs must have `userId`, `actorId`, and `metadata` with email.

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt`

**Step 1: Read both files** (already read above)

**Step 2: Write the failing test**

Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCaseTest.kt`

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.CreateUserUseCase
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class FinishRegistrationUseCaseTest {

    private val ceremonyService = mockk<WebAuthnCeremonyService>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val credentialRepository = mockk<com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository>(relaxed = true)
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val challengeStore = mockk<RedisChallengeStore>()

    private val useCase = FinishRegistrationUseCase(
        ceremonyService, createUserUseCase, credentialRepository, issueTokenUseCase, challengeStore
    )

    @Test
    fun `result includes userId and email`() {
        val userId = UUID.randomUUID()
        val user = mockk<User> {
            every { id } returns userId
            every { email } returns "test@example.com"
        }
        every { challengeStore.consumeSessionData(any(), "email") } returns "test@example.com"
        every { ceremonyService.verifyAttestation(any(), any(), any()) } returns mockk(relaxed = true)
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(user)
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(
            FinishRegistrationUseCase.Command("session", "cdj", "att", null)
        )

        assert(result.userId == userId)
        assert(result.email == "test@example.com")
    }
}
```

**Step 3: Run test to verify it fails**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.FinishRegistrationUseCaseTest"
```

Expected: FAIL — `result.userId` doesn't exist yet.

**Step 4: Update FinishRegistrationUseCase — expose userId and email in Result**

In `FinishRegistrationUseCase.kt`, change:
```kotlin
// BEFORE
data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

fun execute(command: Command): Result {
    val email = challengeStore.consumeSessionData(command.sessionId, "email")
        ?: throw BadRequestException("Registration session expired.", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    val credential = ceremonyService.verifyAttestation(...)
    val userResult = createUserUseCase.execute(...)
    credentialRepository.save(...)
    val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(userResult.user))
    return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
}
```

```kotlin
// AFTER
import java.util.UUID

data class Result(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Long,
    val userId: UUID,       // added
    val email: String,      // added
)

fun execute(command: Command): Result {
    val email = challengeStore.consumeSessionData(command.sessionId, "email")
        ?: throw BadRequestException("Registration session expired.", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    val credential = ceremonyService.verifyAttestation(
        command.sessionId, command.clientDataJSON, command.attestationObject
    )
    val userResult = createUserUseCase.execute(
        CreateUserUseCase.Command(email = email, displayName = null, googleSub = null)
    )
    credentialRepository.save(
        PasskeyCredential(
            userId = userResult.user.id,
            credentialId = credential.credentialId,
            publicKeyCose = credential.publicKeyCose,
            signCounter = credential.signCounter,
            aaguid = credential.aaguid,
            displayName = command.displayName,
        )
    )
    val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(userResult.user))
    return Result(
        accessToken = tokens.accessToken,
        refreshToken = tokens.refreshToken,
        expiresIn = tokens.expiresIn,
        userId = userResult.user.id,    // added
        email = email,                  // added
    )
}
```

**Step 5: Update RegisterController.passkeyFinish() — populate the audit event**

In `RegisterController.kt`, change the `passkeyFinish` method:

```kotlin
// BEFORE
@PostMapping("/passkey/finish")
fun passkeyFinish(@Valid @RequestBody request: RegisterFinishRequest): ApiResponse<TokenResponse> {
    val result = finishRegistrationUseCase.execute(...)
    eventPublisher.publishEvent(AuditDomainEvent(
        eventType = AuditEvent.REGISTRATION_COMPLETED,
    ))
    return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
}
```

```kotlin
// AFTER
@PostMapping("/passkey/finish")
fun passkeyFinish(@Valid @RequestBody request: RegisterFinishRequest): ApiResponse<TokenResponse> {
    val result = finishRegistrationUseCase.execute(
        FinishRegistrationUseCase.Command(
            sessionId = request.sessionId,
            clientDataJSON = request.clientDataJSON,
            attestationObject = request.attestationObject,
            displayName = request.displayName,
        )
    )
    eventPublisher.publishEvent(AuditDomainEvent(
        eventType = AuditEvent.REGISTRATION_COMPLETED,
        userId = result.userId,
        actorId = result.userId,
        metadata = mapOf("email" to result.email),
    ))
    return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
}
```

**Step 6: Run test to verify it passes**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.FinishRegistrationUseCaseTest"
```

Expected: PASS

**Step 7: Run full suite**

```bash
./gradlew test
```

Expected: All pass.

**Step 8: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCaseTest.kt
git commit -m "fix(audit): REGISTRATION_COMPLETED now includes userId, actorId, and email metadata"
```

---

## Task 6: HttpContextExtractor — Shared IP/UserAgent Utility

**Goal:** Single utility reads client IP and User-Agent from the current request (via `RequestContextHolder`) so any class can access them without `HttpServletRequest` in its constructor or method signatures.

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/web/HttpContextExtractor.kt`

**Step 1: Write the failing test**

Create: `src/test/kotlin/com/aibles/iam/shared/web/HttpContextExtractorTest.kt`

```kotlin
package com.aibles.iam.shared.web

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

class HttpContextExtractorTest {

    private val extractor = HttpContextExtractor()

    @AfterEach
    fun clearContext() = RequestContextHolder.resetRequestAttributes()

    private fun bindRequest(configure: MockHttpServletRequest.() -> Unit): MockHttpServletRequest {
        val req = MockHttpServletRequest().apply(configure)
        RequestContextHolder.setRequestAttributes(ServletRequestAttributes(req))
        return req
    }

    @Test
    fun `clientIp returns remoteAddr when no XFF header`() {
        bindRequest { remoteAddr = "192.168.1.1" }
        assert(extractor.clientIp() == "192.168.1.1")
    }

    @Test
    fun `clientIp returns first XFF IP`() {
        bindRequest {
            remoteAddr = "10.0.0.1"
            addHeader("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
        }
        assert(extractor.clientIp() == "203.0.113.5")
    }

    @Test
    fun `userAgent returns header value`() {
        bindRequest { addHeader("User-Agent", "Mozilla/5.0") }
        assert(extractor.userAgent() == "Mozilla/5.0")
    }

    @Test
    fun `clientIp returns null when no request context`() {
        // No RequestContextHolder set
        assert(extractor.clientIp() == null)
    }

    @Test
    fun `userAgent returns null when no request context`() {
        assert(extractor.userAgent() == null)
    }
}
```

**Step 2: Run test to verify it fails**

```bash
./gradlew test --tests "com.aibles.iam.shared.web.HttpContextExtractorTest"
```

Expected: FAIL — `HttpContextExtractor` doesn't exist.

**Step 3: Implement HttpContextExtractor**

```kotlin
package com.aibles.iam.shared.web

import org.springframework.stereotype.Component
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

/**
 * Reads HTTP request metadata (IP, User-Agent) from the current request context.
 * Works anywhere in the call stack during a request — use cases, services, handlers.
 * Returns null when called outside of a request context (e.g., in background tasks).
 */
@Component
class HttpContextExtractor {

    fun clientIp(): String? {
        val request = currentRequest() ?: return null
        val xff = request.getHeader("X-Forwarded-For")
        if (!xff.isNullOrBlank()) return xff.split(",").first().trim()
        return request.remoteAddr
    }

    fun userAgent(): String? = currentRequest()?.getHeader("User-Agent")

    private fun currentRequest() =
        (RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes)?.request
}
```

**Step 4: Run test to verify it passes**

```bash
./gradlew test --tests "com.aibles.iam.shared.web.HttpContextExtractorTest"
```

Expected: PASS

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/web/HttpContextExtractor.kt \
        src/test/kotlin/com/aibles/iam/shared/web/HttpContextExtractorTest.kt
git commit -m "feat(audit): HttpContextExtractor — shared IP/UA from RequestContextHolder"
```

---

## Task 7: Propagate IP/UserAgent to All Audit Events (Problem 3)

**Goal:** Every `AuditDomainEvent` published anywhere now carries `ipAddress` and `userAgent`.

**Files to modify:**
- `src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt`
- `src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt`
- `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`
- `src/main/kotlin/com/aibles/iam/authorization/usecase/RefreshTokenUseCase.kt`
- `src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt`
- `src/main/kotlin/com/aibles/iam/identity/usecase/CreateUserUseCase.kt`

**Step 1: Inject HttpContextExtractor into controllers and affected use cases**

### RegisterController.kt
Add to constructor: `private val httpContextExtractor: HttpContextExtractor`

Update every `eventPublisher.publishEvent(...)` call to include:
```kotlin
ipAddress = httpContextExtractor.clientIp(),
userAgent = httpContextExtractor.userAgent(),
```

All 3 events: `REGISTRATION_OTP_SENT`, `REGISTRATION_OTP_VERIFIED`, `REGISTRATION_COMPLETED`.

### PasskeyController.kt
Add to constructor: `private val httpContextExtractor: HttpContextExtractor`

Update `PASSKEY_OTP_SENT` and `PASSKEY_OTP_VERIFIED` events:
```kotlin
ipAddress = httpContextExtractor.clientIp(),
userAgent = httpContextExtractor.userAgent(),
```

### GoogleOAuth2SuccessHandler.kt
`HttpServletRequest` is already available as method parameter. Update both `LOGIN_GOOGLE_SUCCESS` events:
```kotlin
// Use httpContextExtractor instead of direct request to stay consistent
// OR read directly since request is already in scope:
ipAddress = httpContextExtractor.clientIp(),
userAgent = httpContextExtractor.userAgent(),
```
Add `httpContextExtractor: HttpContextExtractor` to constructor.

### RefreshTokenUseCase.kt
Add to constructor: `private val httpContextExtractor: HttpContextExtractor`

Update `TOKEN_REFRESHED` event:
```kotlin
eventPublisher.publishEvent(AuditDomainEvent(
    eventType = AuditEvent.TOKEN_REFRESHED,
    userId = userId,
    actorId = userId,
    ipAddress = httpContextExtractor.clientIp(),
    userAgent = httpContextExtractor.userAgent(),
))
```

### RevokeTokenUseCase.kt
Add to constructor: `private val httpContextExtractor: HttpContextExtractor`

Update `TOKEN_REVOKED` event:
```kotlin
eventPublisher.publishEvent(AuditDomainEvent(
    eventType = AuditEvent.TOKEN_REVOKED,
    userId = userId,
    actorId = userId,
    ipAddress = httpContextExtractor.clientIp(),
    userAgent = httpContextExtractor.userAgent(),
))
```

### CreateUserUseCase.kt
Add to constructor: `private val httpContextExtractor: HttpContextExtractor`

Update `USER_CREATED` event:
```kotlin
eventPublisher.publishEvent(AuditDomainEvent(
    eventType = AuditEvent.USER_CREATED,
    userId = saved.id,
    actorId = saved.id,
    ipAddress = httpContextExtractor.clientIp(),
    userAgent = httpContextExtractor.userAgent(),
    metadata = mapOf("email" to saved.email),
))
```

**Step 2: Run full test suite**

```bash
./gradlew test
```

Expected: All pass. MockK tests using `mockk(relaxed = true)` for `HttpContextExtractor` will return null for IP/UA — that's correct behavior.

**Step 3: Manual smoke test — register flow**

```bash
# 1. Send OTP
curl -s -X POST http://localhost:8080/api/v1/auth/register/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'

# After completing registration, check audit_logs table:
# psql -h localhost -U iam -d iam -c "SELECT event_type, user_id, ip_address, user_agent FROM audit_logs ORDER BY created_at DESC LIMIT 10;"
# ip_address and user_agent should NO LONGER be null
```

**Step 4: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt \
        src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt \
        src/main/kotlin/com/aibles/iam/authorization/usecase/RefreshTokenUseCase.kt \
        src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt \
        src/main/kotlin/com/aibles/iam/identity/usecase/CreateUserUseCase.kt
git commit -m "fix(audit): propagate ip_address and user_agent to all audit events"
```

---

## Task 8: Add Missing Audit Events (Bonus)

**Goal:** `PASSKEY_REGISTERED`, `PASSKEY_AUTHENTICATED`, and `PASSKEY_DELETED` are defined in `AuditEvent` but never published.

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt`

**Step 1: Add userId + email to AuthenticatePasskeyFinishUseCase.Result**

`AuthenticatePasskeyFinishUseCase.Result` currently only has tokens. The controller has no user context after authenticate/finish (it's an unauthenticated flow). Add `userId` to Result:

```kotlin
data class Result(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Long,
    val userId: UUID,   // added — already available as `user.id` at Step 8 in execute()
)
```

In `execute()`, update the return:
```kotlin
return Result(
    accessToken = tokens.accessToken,
    refreshToken = tokens.refreshToken,
    expiresIn = tokens.expiresIn,
    userId = user.id,
)
```

**Step 2: Publish missing events in PasskeyController**

### registerFinish — add PASSKEY_REGISTERED
```kotlin
@PostMapping("/register/finish")
fun registerFinish(
    @AuthenticationPrincipal principal: Jwt,
    @Valid @RequestBody request: RegisterFinishRequest,
): ApiResponse<Unit> {
    val userId = UUID.fromString(principal.subject)
    registerPasskeyFinishUseCase.execute(
        RegisterPasskeyFinishUseCase.Command(
            userId = userId,
            sessionId = request.sessionId,
            clientDataJSON = request.clientDataJSON,
            attestationObject = request.attestationObject,
            displayName = request.displayName,
        )
    )
    eventPublisher.publishEvent(AuditDomainEvent(
        eventType = AuditEvent.PASSKEY_REGISTERED,
        userId = userId,
        actorId = userId,
        ipAddress = httpContextExtractor.clientIp(),
        userAgent = httpContextExtractor.userAgent(),
        metadata = request.displayName?.let { mapOf("displayName" to it) },
    ))
    return ApiResponse.ok(Unit)
}
```

### authenticateFinish — add PASSKEY_AUTHENTICATED
```kotlin
@PostMapping("/authenticate/finish")
fun authenticateFinish(
    @Valid @RequestBody request: AuthenticateFinishRequest,
): ApiResponse<TokenResponse> {
    val result = authenticatePasskeyFinishUseCase.execute(
        AuthenticatePasskeyFinishUseCase.Command(
            credentialId = request.credentialId,
            sessionId = request.sessionId,
            clientDataJSON = request.clientDataJSON,
            authenticatorData = request.authenticatorData,
            signature = request.signature,
            userHandle = request.userHandle,
        )
    )
    eventPublisher.publishEvent(AuditDomainEvent(
        eventType = AuditEvent.PASSKEY_AUTHENTICATED,
        userId = result.userId,
        actorId = result.userId,
        ipAddress = httpContextExtractor.clientIp(),
        userAgent = httpContextExtractor.userAgent(),
    ))
    return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
}
```

### deleteCredential — add PASSKEY_DELETED
```kotlin
@DeleteMapping("/credentials/{id}")
@ResponseStatus(HttpStatus.NO_CONTENT)
fun deleteCredential(
    @AuthenticationPrincipal principal: Jwt,
    @PathVariable id: UUID,
) {
    val userId = UUID.fromString(principal.subject)
    deletePasskeyUseCase.execute(DeletePasskeyUseCase.Command(userId, id))
    eventPublisher.publishEvent(AuditDomainEvent(
        eventType = AuditEvent.PASSKEY_DELETED,
        userId = userId,
        actorId = userId,
        ipAddress = httpContextExtractor.clientIp(),
        userAgent = httpContextExtractor.userAgent(),
        metadata = mapOf("credentialId" to id.toString()),
    ))
}
```

**Step 3: Run full test suite**

```bash
./gradlew test
```

Expected: All pass.

**Step 4: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt
git commit -m "feat(audit): publish PASSKEY_REGISTERED, PASSKEY_AUTHENTICATED, PASSKEY_DELETED events"
```

---

## Verification Checklist

After all tasks complete, verify:

```sql
-- All recent audit events should have ip_address and user_agent
SELECT event_type, user_id, actor_id, ip_address, user_agent, metadata
FROM audit_logs
ORDER BY created_at DESC
LIMIT 20;

-- REGISTRATION_COMPLETED must have user_id, actor_id, metadata with email
SELECT * FROM audit_logs WHERE event_type = 'REGISTRATION_COMPLETED';

-- No nulls for ip_address or user_agent in any recent event
SELECT COUNT(*) FROM audit_logs
WHERE ip_address IS NULL OR user_agent IS NULL;
```

Log output check:
```bash
# Should see lines like:
# 14:32:15.123 DEBUG [a1b2c3d4] [127.0.0.1] FinishRegistrationUseCase - FinishRegistrationUseCase starting
# 14:32:15.456 DEBUG [a1b2c3d4] [127.0.0.1] FinishRegistrationUseCase - FinishRegistrationUseCase completed in 312ms
# 14:32:15.460 WARN  [a1b2c3d4] [127.0.0.1] GlobalExceptionHandler - Domain exception [USER_NOT_FOUND]: ...
```
