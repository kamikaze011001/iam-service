# Fix Google OAuth2 Popup + Passkey Email OTP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix Google login popup to close and relay tokens to the parent window via `postMessage`; gate passkey registration behind a 6-digit email OTP that the user must verify before the WebAuthn ceremony starts.

**Architecture:**
- **Fix 1 (popup):** `GoogleOAuth2SuccessHandler` currently writes JSON into the popup's response body, leaving the popup open. Change it to respond with a minimal HTML page that calls `window.opener.postMessage(tokens, frontendOrigin)` then `window.close()`. Requires a new `FRONTEND_URL` config property so the handler knows the allowed target origin.
- **Fix 2 (OTP):** Add two new endpoints (`send-otp`, `verify-otp`) before `register/start`. OTP codes are 6-digit numerics stored in Redis with a 5-minute TTL. After correct verification, a short-lived `otpToken` UUID is stored in Redis (10-min TTL); `register/start` consumes it atomically before generating the WebAuthn challenge. Email is sent via Spring Boot Mail (SMTP).

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Spring Security, Redis (StringRedisTemplate), Spring Boot Mail (JavaMailSender), MockK for unit tests. Java 24 is active — run `./gradlew` directly.

---

## Fix 1 — Google OAuth2 Popup Close

### Task 1: Add `frontendUrl` config property

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/CorsProperties.kt`
- Modify: `src/main/resources/application.yml`

**Step 1: Read CorsProperties to understand the existing pattern**

File: `src/main/kotlin/com/aibles/iam/shared/config/CorsProperties.kt`

**Step 2: Add `frontendUrl` to the existing `CorsProperties` (or create a dedicated `FrontendProperties`)**

Since `CorsProperties` already holds `allowedOrigins` (the frontend origin), add `frontendUrl` there to avoid a second config class:

```kotlin
// CorsProperties.kt — add one field
@ConfigurationProperties(prefix = "cors")
data class CorsProperties(
    val allowedOrigins: List<String> = listOf("http://localhost:3000"),
    val allowedMethods: List<String> = listOf("GET","POST","PATCH","DELETE","OPTIONS"),
    val allowedHeaders: List<String> = listOf("Authorization","Content-Type"),
    val maxAge: Long = 3600,
    val frontendUrl: String = "http://localhost:3000",   // ← new
)
```

**Step 3: Add env var to `application.yml`**

```yaml
cors:
  allowed-origins: ${CORS_ALLOWED_ORIGINS:http://localhost:3000}
  allowed-methods: GET,POST,PATCH,DELETE,OPTIONS
  allowed-headers: Authorization,Content-Type
  max-age: 3600
  frontend-url: ${FRONTEND_URL:http://localhost:3000}   # ← new line
```

**Step 4: Run tests to confirm nothing is broken**

```bash
./gradlew test
```
Expected: all green.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/config/CorsProperties.kt \
        src/main/resources/application.yml
git commit -m "feat: add frontendUrl to CorsProperties for OAuth2 popup postMessage"
```

---

### Task 2: Rewrite `GoogleOAuth2SuccessHandler` to use `postMessage` + `window.close()`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandlerTest.kt` (create if not exists)

**Root cause:** The handler calls `objectMapper.writeValue(response.writer, body)` and returns — this leaves the popup showing raw JSON. The fix returns an HTML payload that uses `window.opener.postMessage` to relay tokens to the parent page, then closes itself.

**Step 1: Write the failing test**

Create `src/test/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandlerTest.kt`:

```kotlin
package com.aibles.iam.authentication.infra

import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.authentication.usecase.SyncGoogleUserUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.config.CorsProperties
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.springframework.context.ApplicationEventPublisher
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import java.util.UUID
import kotlin.test.Test

class GoogleOAuth2SuccessHandlerTest {

    private val syncUseCase = mockk<SyncGoogleUserUseCase>()
    private val loginUseCase = mockk<LoginWithGoogleUseCase>()
    private val objectMapper = ObjectMapper().registerKotlinModule()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val corsProperties = CorsProperties(frontendUrl = "http://localhost:3000")

    private val handler = GoogleOAuth2SuccessHandler(
        syncGoogleUserUseCase = syncUseCase,
        loginWithGoogleUseCase = loginUseCase,
        objectMapper = objectMapper,
        eventPublisher = eventPublisher,
        corsProperties = corsProperties,
    )

    @Test
    fun `success response is HTML that calls postMessage and closes window`() {
        val userId = UUID.randomUUID()
        val mockUser = mockk<User> { every { id } returns userId; every { email } returns "u@test.com" }
        val mockOidc = mockk<OidcUser>()
        val mockAuth = mockk<Authentication> { every { principal } returns mockOidc }

        every { loginUseCase.execute(any()) } returns LoginWithGoogleUseCase.Result(
            user = mockUser,
            accessToken = "access-123",
            refreshToken = "refresh-456",
            expiresIn = 900,
        )

        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()

        handler.onAuthenticationSuccess(request, response, mockAuth)

        assertThat(response.contentType).contains("text/html")
        val body = response.contentAsString
        assertThat(body).contains("window.opener.postMessage")
        assertThat(body).contains("access-123")
        assertThat(body).contains("refresh-456")
        assertThat(body).contains("http://localhost:3000")
        assertThat(body).contains("window.close()")
    }
}
```

**Step 2: Run to confirm it fails**

```bash
./gradlew test --tests "*.GoogleOAuth2SuccessHandlerTest"
```
Expected: compile error (constructor mismatch) or test failure.

**Step 3: Rewrite `GoogleOAuth2SuccessHandler`**

```kotlin
package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.authentication.usecase.SyncGoogleUserUseCase
import com.aibles.iam.shared.config.CorsProperties
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2SuccessHandler(
    private val syncGoogleUserUseCase: SyncGoogleUserUseCase,
    private val loginWithGoogleUseCase: LoginWithGoogleUseCase,
    private val objectMapper: ObjectMapper,
    private val eventPublisher: ApplicationEventPublisher,
    private val corsProperties: CorsProperties,
    private val requestCache: HttpSessionRequestCache = HttpSessionRequestCache(),
    private val savedRequestHandler: SavedRequestAwareAuthenticationSuccessHandler =
        SavedRequestAwareAuthenticationSuccessHandler(),
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val principal = authentication.principal
        if (principal !is OidcUser) {
            response.status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR
            response.contentType = MediaType.TEXT_HTML_VALUE
            response.writer.write(errorHtml("Unexpected authentication principal type"))
            return
        }

        // AS authorization code flow: just sync the user and let the AS handle redirect.
        val savedRequest = requestCache.getRequest(request, response)
        if (savedRequest != null) {
            val result = syncGoogleUserUseCase.execute(SyncGoogleUserUseCase.Command(principal))
            eventPublisher.publishEvent(AuditDomainEvent(
                eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
                userId = result.user.id,
                actorId = result.user.id,
                metadata = mapOf("email" to result.user.email),
            ))
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication)
            return
        }

        // Direct Google login (popup flow): issue tokens, relay via postMessage, close popup.
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
            userId = result.user.id,
            actorId = result.user.id,
            metadata = mapOf("email" to result.user.email),
        ))

        response.status = HttpServletResponse.SC_OK
        response.contentType = MediaType.TEXT_HTML_VALUE
        response.writer.write(
            successHtml(
                accessToken = result.accessToken,
                refreshToken = result.refreshToken,
                expiresIn = result.expiresIn,
                targetOrigin = corsProperties.frontendUrl,
            )
        )
    }

    private fun successHtml(
        accessToken: String,
        refreshToken: String,
        expiresIn: Long,
        targetOrigin: String,
    ): String {
        // Serialize via Jackson to ensure correct JSON escaping inside the script.
        val payload = objectMapper.writeValueAsString(
            mapOf(
                "type" to "GOOGLE_AUTH_SUCCESS",
                "accessToken" to accessToken,
                "refreshToken" to refreshToken,
                "expiresIn" to expiresIn,
            )
        )
        return """
            <!DOCTYPE html>
            <html>
            <head><title>Authenticating…</title></head>
            <body>
            <script>
              (function() {
                var payload = $payload;
                var origin  = ${objectMapper.writeValueAsString(targetOrigin)};
                if (window.opener) {
                  window.opener.postMessage(payload, origin);
                }
                window.close();
              })();
            </script>
            <p>Authentication complete. This window will close automatically.</p>
            </body>
            </html>
        """.trimIndent()
    }

    private fun errorHtml(message: String): String = """
        <!DOCTYPE html><html><body>
        <script>
          if (window.opener) {
            window.opener.postMessage({type:'GOOGLE_AUTH_ERROR',message:${objectMapper.writeValueAsString(message)}}, '*');
          }
          window.close();
        </script>
        <p>Authentication failed: $message</p>
        </body></html>
    """.trimIndent()
}
```

**Step 4: Run the test**

```bash
./gradlew test --tests "*.GoogleOAuth2SuccessHandlerTest"
```
Expected: PASS.

**Step 5: Run all tests**

```bash
./gradlew test
```
Expected: all green.

**Step 6: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt \
        src/test/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandlerTest.kt
git commit -m "fix(auth): close Google OAuth2 popup via postMessage instead of raw JSON response"
```

---

## Fix 2 — Email OTP Gate for Passkey Registration

### Task 3: Add Spring Mail dependency and config

**Files:**
- Modify: `build.gradle.kts`
- Modify: `src/main/resources/application.yml`

**Step 1: Add the dependency**

In `build.gradle.kts`, inside the `dependencies { }` block, add:

```kotlin
implementation("org.springframework.boot:spring-boot-starter-mail")
```

**Step 2: Add mail configuration to `application.yml`**

```yaml
spring:
  mail:
    host: ${MAIL_HOST:smtp.gmail.com}
    port: ${MAIL_PORT:587}
    username: ${MAIL_USERNAME:}
    password: ${MAIL_PASSWORD:}
    properties:
      mail:
        smtp:
          auth: true
          starttls:
            enable: true
mail:
  from: ${MAIL_FROM:noreply@yourdomain.com}
  from-name: ${MAIL_FROM_NAME:IAM Service}
```

**Step 3: Commit**

```bash
git add build.gradle.kts src/main/resources/application.yml
git commit -m "feat(otp): add Spring Boot Mail dependency and SMTP config"
```

---

### Task 4: Add OTP error codes and audit events

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`
- Modify: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt`

**Step 1: Add to `ErrorCode.kt`**

```kotlin
// Add inside the enum, in the Authentication section:
OTP_INVALID(HttpStatus.BAD_REQUEST),
OTP_EXPIRED(HttpStatus.BAD_REQUEST),
OTP_MAX_ATTEMPTS(HttpStatus.TOO_MANY_REQUESTS),
```

**Step 2: Add to `AuditEvent.kt`**

```kotlin
// Add inside the enum:
PASSKEY_OTP_SENT,
PASSKEY_OTP_VERIFIED,
```

**Step 3: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt \
        src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt
git commit -m "feat(otp): add OTP error codes and audit events"
```

---

### Task 5: Create `MailProperties` config and `EmailService`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/config/MailProperties.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/infra/EmailService.kt`

**Step 1: Create `MailProperties.kt`**

```kotlin
package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "mail")
data class MailProperties(
    val from: String = "noreply@yourdomain.com",
    val fromName: String = "IAM Service",
)
```

**Step 2: Create `EmailService.kt`**

```kotlin
package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.config.MailProperties
import org.springframework.mail.javamail.JavaMailSender
import org.springframework.mail.javamail.MimeMessageHelper
import org.springframework.stereotype.Component

@Component
class EmailService(
    private val mailSender: JavaMailSender,
    private val mailProperties: MailProperties,
) {
    fun sendOtp(toEmail: String, otpCode: String) {
        val message = mailSender.createMimeMessage()
        val helper = MimeMessageHelper(message, false, "UTF-8")
        helper.setFrom("${mailProperties.fromName} <${mailProperties.from}>")
        helper.setTo(toEmail)
        helper.setSubject("Your passkey registration code")
        helper.setText(
            """
            Your one-time verification code is:

                $otpCode

            This code expires in 5 minutes. Do not share it with anyone.
            """.trimIndent()
        )
        mailSender.send(message)
    }
}
```

**Step 3: Enable `MailProperties` in the main config**

In `SecurityConfig.kt` or the main application class, add `@EnableConfigurationProperties(MailProperties::class)`.
Actually, add it to the Spring Boot main application class or a `@Configuration` class — the cleanest place is a new `MailConfig.kt`:

```kotlin
package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@EnableConfigurationProperties(MailProperties::class)
class MailConfig
```

**Step 4: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/config/MailProperties.kt \
        src/main/kotlin/com/aibles/iam/shared/config/MailConfig.kt \
        src/main/kotlin/com/aibles/iam/authentication/infra/EmailService.kt
git commit -m "feat(otp): add EmailService with JavaMailSender for OTP delivery"
```

---

### Task 6: Create `RedisOtpStore`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt`

**Redis key scheme:**
- `otp:reg:<userId>` → `"<6-digit-code>"` — TTL 5 min
- `otp:reg:attempts:<userId>` → `"<count>"` — TTL 5 min (reset on each new OTP send)
- `otp:reg:ok:<otpToken>` → `"<userId>"` — TTL 10 min (written on successful verify)

**Step 1: Write the test**

```kotlin
package com.aibles.iam.authentication.infra

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.junit.jupiter.Testcontainers
import java.util.UUID

// NOTE: this is an integration test — needs a running Redis.
// Add @Testcontainers + a Redis container if one isn't already configured.
// For simplicity, run docker compose up -d before running tests locally.
@SpringBootTest
class RedisOtpStoreTest {

    @Autowired lateinit var template: StringRedisTemplate
    @Autowired lateinit var store: RedisOtpStore

    @BeforeEach fun clean() { template.connectionFactory!!.connection.flushAll() }

    @Test fun `stores OTP and can retrieve it`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "123456")
        assertThat(store.getOtp(userId)).isEqualTo("123456")
    }

    @Test fun `getOtp returns null after deletion`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "999999")
        store.deleteOtp(userId)
        assertThat(store.getOtp(userId)).isNull()
    }

    @Test fun `incrementAttempts returns current count`() {
        val userId = UUID.randomUUID()
        store.saveOtp(userId, "111111")
        assertThat(store.incrementAttempts(userId)).isEqualTo(1L)
        assertThat(store.incrementAttempts(userId)).isEqualTo(2L)
    }

    @Test fun `saves and consumes otpToken`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.saveOtpToken(token, userId)
        assertThat(store.consumeOtpToken(token)).isEqualTo(userId)
        assertThat(store.consumeOtpToken(token)).isNull()  // one-time
    }
}
```

**Step 2: Run to confirm it fails**

```bash
./gradlew test --tests "*.RedisOtpStoreTest"
```
Expected: compile error (class not found).

**Step 3: Implement `RedisOtpStore`**

```kotlin
package com.aibles.iam.authentication.infra

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.UUID

@Component
class RedisOtpStore(private val template: StringRedisTemplate) {

    companion object {
        private const val OTP_PREFIX      = "otp:reg:"
        private const val ATTEMPTS_PREFIX = "otp:reg:attempts:"
        private const val TOKEN_PREFIX    = "otp:reg:ok:"
        private val OTP_TTL      = Duration.ofMinutes(5)
        private val TOKEN_TTL    = Duration.ofMinutes(10)
        private const val MAX_ATTEMPTS = 3L
    }

    fun saveOtp(userId: UUID, code: String) {
        template.opsForValue().set("$OTP_PREFIX$userId", code, OTP_TTL)
        template.delete("$ATTEMPTS_PREFIX$userId")   // reset attempts on resend
    }

    fun getOtp(userId: UUID): String? =
        template.opsForValue().get("$OTP_PREFIX$userId")

    fun deleteOtp(userId: UUID) {
        template.delete("$OTP_PREFIX$userId")
        template.delete("$ATTEMPTS_PREFIX$userId")
    }

    /** Increments and returns the new attempt count. */
    fun incrementAttempts(userId: UUID): Long {
        val key = "$ATTEMPTS_PREFIX$userId"
        val count = template.opsForValue().increment(key) ?: 1L
        if (count == 1L) template.expire(key, OTP_TTL)   // set TTL on first increment
        return count
    }

    val maxAttempts: Long get() = MAX_ATTEMPTS

    fun saveOtpToken(token: String, userId: UUID) {
        template.opsForValue().set("$TOKEN_PREFIX$token", userId.toString(), TOKEN_TTL)
    }

    /** Returns the userId the token was issued for, or null if expired/not found. Deletes on read (one-time). */
    fun consumeOtpToken(token: String): UUID? =
        template.opsForValue().getAndDelete("$TOKEN_PREFIX$token")?.let { UUID.fromString(it) }
}
```

**Step 4: Run the test**

```bash
./gradlew test --tests "*.RedisOtpStoreTest"
```
Expected: PASS (needs Redis running — `docker compose up -d`).

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt \
        src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt
git commit -m "feat(otp): add RedisOtpStore for OTP code and verified-session management"
```

---

### Task 7: Create `SendPasskeyOtpUseCase`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt`

**Step 1: Write the failing test**

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.GetUserUseCase
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class SendPasskeyOtpUseCaseTest {

    private val getUserUseCase = mockk<GetUserUseCase>()
    private val otpStore       = mockk<RedisOtpStore>(relaxed = true)
    private val emailService   = mockk<EmailService>(relaxed = true)
    private val useCase = SendPasskeyOtpUseCase(getUserUseCase, otpStore, emailService)

    @Test
    fun `sends OTP to the user email and stores it`() {
        val userId = UUID.randomUUID()
        val user   = mockk<User> { every { email } returns "user@test.com" }
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user

        val codeSlot = slot<String>()
        every { otpStore.saveOtp(userId, capture(codeSlot)) } returns Unit

        useCase.execute(SendPasskeyOtpUseCase.Command(userId))

        val code = codeSlot.captured
        assertThat(code).matches("\\d{6}")
        verify(exactly = 1) { emailService.sendOtp("user@test.com", code) }
    }
}
```

**Step 2: Run to confirm it fails**

```bash
./gradlew test --tests "*.SendPasskeyOtpUseCaseTest"
```
Expected: compile error.

**Step 3: Implement `SendPasskeyOtpUseCase`**

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.usecase.GetUserUseCase
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.UUID

@Component
class SendPasskeyOtpUseCase(
    private val getUserUseCase: GetUserUseCase,
    private val otpStore: RedisOtpStore,
    private val emailService: EmailService,
) {
    data class Command(val userId: UUID)

    fun execute(command: Command) {
        val user = getUserUseCase.execute(GetUserUseCase.Query(command.userId))
        val code = String.format("%06d", SecureRandom().nextInt(1_000_000))
        otpStore.saveOtp(command.userId, code)
        emailService.sendOtp(user.email, code)
    }
}
```

**Step 4: Run the test**

```bash
./gradlew test --tests "*.SendPasskeyOtpUseCaseTest"
```
Expected: PASS.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt
git commit -m "feat(otp): add SendPasskeyOtpUseCase — generates and emails 6-digit OTP"
```

---

### Task 8: Create `VerifyPasskeyOtpUseCase`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCaseTest.kt`

**Step 1: Write the failing test**

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class VerifyPasskeyOtpUseCaseTest {

    private val otpStore = mockk<RedisOtpStore>(relaxed = true)
    private val useCase  = VerifyPasskeyOtpUseCase(otpStore)

    @Test
    fun `returns otpToken on correct code`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns "123456"
        every { otpStore.incrementAttempts(userId) } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val result = useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))

        assertThat(result.otpToken).isNotBlank()
        verify { otpStore.deleteOtp(userId) }
        verify { otpStore.saveOtpToken(result.otpToken, userId) }
    }

    @Test
    fun `throws OTP_INVALID on wrong code`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns "999999"
        every { otpStore.incrementAttempts(userId) } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_INVALID)
    }

    @Test
    fun `throws OTP_EXPIRED when no OTP in store`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns null
        every { otpStore.incrementAttempts(userId) } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }

    @Test
    fun `throws OTP_MAX_ATTEMPTS when attempts exceeded`() {
        val userId = UUID.randomUUID()
        every { otpStore.getOtp(userId) } returns "123456"
        every { otpStore.incrementAttempts(userId) } returns 4L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyPasskeyOtpUseCase.Command(userId, "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_MAX_ATTEMPTS)
    }
}
```

**Step 2: Run to confirm it fails**

```bash
./gradlew test --tests "*.VerifyPasskeyOtpUseCaseTest"
```

**Step 3: Implement `VerifyPasskeyOtpUseCase`**

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class VerifyPasskeyOtpUseCase(private val otpStore: RedisOtpStore) {

    data class Command(val userId: UUID, val code: String)
    data class Result(val otpToken: String)

    fun execute(command: Command): Result {
        val attempts = otpStore.incrementAttempts(command.userId)
        if (attempts > otpStore.maxAttempts) {
            throw BadRequestException("Too many OTP attempts. Please request a new code.", ErrorCode.OTP_MAX_ATTEMPTS)
        }

        val stored = otpStore.getOtp(command.userId)
            ?: throw BadRequestException("OTP expired. Please request a new code.", ErrorCode.OTP_EXPIRED)

        if (stored != command.code) {
            throw BadRequestException("Invalid OTP code.", ErrorCode.OTP_INVALID)
        }

        val otpToken = UUID.randomUUID().toString()
        otpStore.deleteOtp(command.userId)
        otpStore.saveOtpToken(otpToken, command.userId)
        return Result(otpToken)
    }
}
```

**Step 4: Run the test**

```bash
./gradlew test --tests "*.VerifyPasskeyOtpUseCaseTest"
```
Expected: PASS.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCaseTest.kt
git commit -m "feat(otp): add VerifyPasskeyOtpUseCase with attempt limiting and one-time token"
```

---

### Task 9: Gate `RegisterPasskeyStartUseCase` with `otpToken`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCaseTest.kt`

**Step 1: Write a new failing test for the OTP gate**

Add to `RegisterPasskeyStartUseCaseTest.kt`:

```kotlin
@Test
fun `throws OTP_EXPIRED when otpToken is not found in store`() {
    every { otpStore.consumeOtpToken("bad-token") } returns null

    val ex = assertThrows<BadRequestException> {
        useCase.execute(
            RegisterPasskeyStartUseCase.Command(
                userId = UUID.randomUUID(),
                userEmail = "u@test.com",
                displayName = "Test",
                otpToken = "bad-token",
            )
        )
    }
    assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
}

@Test
fun `throws UNAUTHORIZED when otpToken belongs to a different user`() {
    val userId = UUID.randomUUID()
    val differentUserId = UUID.randomUUID()
    every { otpStore.consumeOtpToken("valid-token") } returns differentUserId
    // redisChallengeStore should NOT be called

    val ex = assertThrows<UnauthorizedException> {
        useCase.execute(
            RegisterPasskeyStartUseCase.Command(
                userId = userId,
                userEmail = "u@test.com",
                displayName = "Test",
                otpToken = "valid-token",
            )
        )
    }
    assertThat(ex.errorCode).isEqualTo(ErrorCode.UNAUTHORIZED)
}
```

**Step 2: Run to confirm it fails**

```bash
./gradlew test --tests "*.RegisterPasskeyStartUseCaseTest"
```

**Step 3: Modify `RegisterPasskeyStartUseCase`**

Add `otpStore: RedisOtpStore` constructor parameter and `otpToken` to `Command`. Validate token at the start of `execute`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class RegisterPasskeyStartUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val otpStore: RedisOtpStore,
    private val props: WebAuthnProperties,
) {
    data class Command(
        val userId: UUID,
        val userEmail: String,
        val displayName: String?,
        val otpToken: String,
    )
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val userId: String,
        val userEmail: String,
        val userDisplayName: String?,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>> = listOf(
            mapOf("type" to "public-key", "alg" to -7),
            mapOf("type" to "public-key", "alg" to -257),
        ),
        val timeout: Int = 60_000,
        val attestation: String = "none",
    )

    fun execute(command: Command): Result {
        // Consume and validate OTP verified token (one-time, 10-min TTL).
        val tokenOwner = otpStore.consumeOtpToken(command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)
        if (tokenOwner != command.userId) {
            throw UnauthorizedException("OTP token does not match the authenticated user.", ErrorCode.UNAUTHORIZED)
        }

        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        redisChallengeStore.storeChallenge(sessionId, challengeBytes)

        return Result(
            sessionId = sessionId,
            rpId = props.rpId,
            rpName = props.rpName,
            userId = command.userId.toString(),
            userEmail = command.userEmail,
            userDisplayName = command.displayName,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }
}
```

**Step 4: Run all passkey use case tests**

```bash
./gradlew test --tests "*.RegisterPasskeyStartUseCaseTest"
```
Expected: PASS.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCaseTest.kt
git commit -m "feat(otp): gate RegisterPasskeyStartUseCase behind verified otpToken"
```

---

### Task 10: Add `send-otp` and `verify-otp` endpoints; update `RegisterStartRequest`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterStartRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/VerifyOtpRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/VerifyOtpResponse.kt`

**Step 1: Update `RegisterStartRequest`**

```kotlin
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class RegisterStartRequest(
    val displayName: String? = null,
    @field:NotBlank(message = "otpToken is required")
    val otpToken: String,
)
```

**Step 2: Create `VerifyOtpRequest`**

```kotlin
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern

data class VerifyOtpRequest(
    @field:NotBlank
    @field:Pattern(regexp = "\\d{6}", message = "OTP must be exactly 6 digits")
    val code: String,
)
```

**Step 3: Create `VerifyOtpResponse`**

```kotlin
package com.aibles.iam.authentication.api.dto

data class VerifyOtpResponse(val otpToken: String)
```

**Step 4: Update `PasskeyController` — add new endpoints and wire `otpToken` into `registerStart`**

Add the following injections and endpoints:

```kotlin
// New constructor params (add to existing list):
private val sendPasskeyOtpUseCase: SendPasskeyOtpUseCase,
private val verifyPasskeyOtpUseCase: VerifyPasskeyOtpUseCase,

// New endpoint — send OTP
@PostMapping("/register/send-otp")
@ResponseStatus(HttpStatus.ACCEPTED)
fun sendOtp(@AuthenticationPrincipal principal: Jwt): ApiResponse<Unit> {
    val userId = UUID.fromString(principal.subject)
    sendPasskeyOtpUseCase.execute(SendPasskeyOtpUseCase.Command(userId))
    return ApiResponse.ok(Unit)
}

// New endpoint — verify OTP
@PostMapping("/register/verify-otp")
fun verifyOtp(
    @AuthenticationPrincipal principal: Jwt,
    @Valid @RequestBody request: VerifyOtpRequest,
): ApiResponse<VerifyOtpResponse> {
    val userId = UUID.fromString(principal.subject)
    val result = verifyPasskeyOtpUseCase.execute(
        VerifyPasskeyOtpUseCase.Command(userId, request.code)
    )
    return ApiResponse.ok(VerifyOtpResponse(result.otpToken))
}
```

Update existing `registerStart` to pass `otpToken` from request:

```kotlin
@PostMapping("/register/start")
fun registerStart(
    @AuthenticationPrincipal principal: Jwt,
    @Valid @RequestBody request: RegisterStartRequest,
): ApiResponse<RegisterPasskeyStartUseCase.Result> {
    val userId = UUID.fromString(principal.subject)
    val user = getUserUseCase.execute(GetUserUseCase.Query(userId))
    val result = registerPasskeyStartUseCase.execute(
        RegisterPasskeyStartUseCase.Command(
            userId = userId,
            userEmail = user.email,
            displayName = request.displayName,
            otpToken = request.otpToken,      // ← new
        )
    )
    return ApiResponse.ok(result)
}
```

**Step 5: Add audit events in controller for OTP actions**

In `sendOtp`, after the use case call, publish:
```kotlin
eventPublisher.publishEvent(AuditDomainEvent(
    eventType = AuditEvent.PASSKEY_OTP_SENT,
    userId = userId,
    actorId = userId,
))
```

In `verifyOtp`, after successful verification, publish:
```kotlin
eventPublisher.publishEvent(AuditDomainEvent(
    eventType = AuditEvent.PASSKEY_OTP_VERIFIED,
    userId = userId,
    actorId = userId,
))
```

This requires injecting `ApplicationEventPublisher` into `PasskeyController`.

**Step 6: Run all tests**

```bash
./gradlew test
```
Expected: all green. Fix any compile errors from the updated constructor signatures.

**Step 7: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterStartRequest.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/dto/VerifyOtpRequest.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/dto/VerifyOtpResponse.kt
git commit -m "feat(otp): add send-otp and verify-otp endpoints; gate register/start with otpToken"
```

---

### Task 11: Final verification and PR

**Step 1: Run the full test suite**

```bash
./gradlew test
```
Expected: all green.

**Step 2: Start the service and do a manual smoke test**

```bash
docker compose up -d
./gradlew bootRun
```

Full new passkey registration flow:
```bash
TOKEN="<your-jwt-access-token>"

# 1. Send OTP
curl -s -X POST http://localhost:8080/api/v1/auth/passkey/register/send-otp \
  -H "Authorization: Bearer $TOKEN"
# → check email for 6-digit code

# 2. Verify OTP
curl -s -X POST http://localhost:8080/api/v1/auth/passkey/register/verify-otp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}' | jq
# → {"success":true,"data":{"otpToken":"<uuid>"},...}

# 3. Start registration (with otpToken)
curl -s -X POST http://localhost:8080/api/v1/auth/passkey/register/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"My Passkey","otpToken":"<uuid from step 2>"}' | jq
# → WebAuthn challenge response
```

For the popup fix, open the Google login popup from the frontend and confirm the popup closes automatically and tokens arrive via `window.addEventListener('message', ...)`.

**Step 3: Create PR and merge**

```bash
gh pr create \
  --title "fix: Google popup postMessage close + passkey email OTP gate" \
  --body "Closes #<issue>" \
  --base main

gh pr merge <pr-number> --squash --delete-branch
git checkout main && git pull origin main
```

---

## New API Summary

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/v1/auth/passkey/register/send-otp` | JWT | Sends 6-digit OTP to user's email |
| `POST` | `/api/v1/auth/passkey/register/verify-otp` | JWT | Verifies code; returns `otpToken` |
| `POST` | `/api/v1/auth/passkey/register/start` | JWT | **Modified** — now requires `otpToken` in body |

## Environment Variables Added

| Variable | Default | Description |
|----------|---------|-------------|
| `FRONTEND_URL` | `http://localhost:3000` | Target origin for `postMessage` in popup close |
| `MAIL_HOST` | `smtp.gmail.com` | SMTP server |
| `MAIL_PORT` | `587` | SMTP port |
| `MAIL_USERNAME` | _(required)_ | SMTP username |
| `MAIL_PASSWORD` | _(required)_ | SMTP password |
| `MAIL_FROM` | `noreply@yourdomain.com` | Sender address |
| `MAIL_FROM_NAME` | `IAM Service` | Sender display name |
