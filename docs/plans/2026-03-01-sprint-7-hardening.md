# Sprint 7: Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden the IAM service with rate limiting, CORS configuration, OpenAPI documentation, security headers, and integration tests.

**Architecture:** Each task is independent. Task 1 adds IP-based rate limiting via Bucket4j servlet filter. Task 2 configures CORS via properties-driven `CorsConfigurationSource`. Task 3 adds security headers via Spring Security's `headers()` DSL. Task 4 sets up OpenAPI with a config bean + `@Tag` per controller. Task 5 creates a `BaseIntegrationTest` + two integration test classes covering User CRUD and Audit queries.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Bucket4j 8.10.1, SpringDoc OpenAPI 2.8.3, Testcontainers (PostgreSQL + Redis), JUnit 5, MockK

---

## Task 1: IP-based rate limiting with Bucket4j

**GitHub Issue Title:** `feat(security): add IP-based rate limiting with Bucket4j`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`
- Create: `src/main/kotlin/com/aibles/iam/shared/config/RateLimitProperties.kt`
- Create: `src/main/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilter.kt`
- Modify: `src/main/resources/application.yml`
- Test: `src/test/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilterTest.kt`

### Step 1: Add `RATE_LIMIT_EXCEEDED` to ErrorCode

In `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`, add a new enum value:

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
    RATE_LIMIT_EXCEEDED(HttpStatus.TOO_MANY_REQUESTS),
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

### Step 2: Create RateLimitProperties

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/RateLimitProperties.kt
package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "rate-limit")
data class RateLimitProperties(
    val enabled: Boolean = true,
    val requestsPerMinute: Long = 100,
)
```

### Step 3: Create RateLimitFilter

```kotlin
// src/main/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilter.kt
package com.aibles.iam.shared.ratelimit

import com.aibles.iam.shared.config.RateLimitProperties
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.bucket4j.Bandwidth
import io.github.bucket4j.Bucket
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.http.MediaType
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

@Component
@EnableConfigurationProperties(RateLimitProperties::class)
class RateLimitFilter(
    private val properties: RateLimitProperties,
    private val objectMapper: ObjectMapper,
) : OncePerRequestFilter() {

    private val buckets = ConcurrentHashMap<String, Bucket>()

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (!properties.enabled) {
            filterChain.doFilter(request, response)
            return
        }

        val clientIp = resolveClientIp(request)
        val bucket = buckets.computeIfAbsent(clientIp) { createBucket() }

        if (bucket.tryConsume(1)) {
            filterChain.doFilter(request, response)
        } else {
            response.status = HttpServletResponse.SC_OK + 129 // 429
            response.contentType = MediaType.APPLICATION_JSON_VALUE
            response.setHeader("Retry-After", "60")
            objectMapper.writeValue(
                response.writer,
                ApiResponse.error("RATE_LIMIT_EXCEEDED", "Too many requests. Please try again later."),
            )
        }
    }

    private fun resolveClientIp(request: HttpServletRequest): String =
        request.getHeader("X-Forwarded-For")?.split(",")?.first()?.trim()
            ?: request.remoteAddr

    private fun createBucket(): Bucket {
        val bandwidth = Bandwidth.builder()
            .capacity(properties.requestsPerMinute)
            .refillGreedy(properties.requestsPerMinute, Duration.ofMinutes(1))
            .build()
        return Bucket.builder().addLimit(bandwidth).build()
    }
}
```

**Note:** `SC_OK + 129` is a workaround — actually use the literal `429` directly:

```kotlin
        response.status = 429
```

### Step 4: Add rate-limit properties to application.yml

Append to `src/main/resources/application.yml`:

```yaml
rate-limit:
  enabled: ${RATE_LIMIT_ENABLED:true}
  requests-per-minute: ${RATE_LIMIT_RPM:100}
```

### Step 5: Write the unit test

```kotlin
// src/test/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilterTest.kt
package com.aibles.iam.shared.ratelimit

import com.aibles.iam.shared.config.RateLimitProperties
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import jakarta.servlet.FilterChain
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

class RateLimitFilterTest {

    private val objectMapper: ObjectMapper = jacksonObjectMapper()

    @Test
    fun `allows requests under the limit`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = true, requestsPerMinute = 5), objectMapper)
        val chain = FilterChain { _, _ -> }

        repeat(5) {
            val request = MockHttpServletRequest()
            val response = MockHttpServletResponse()
            filter.doFilterInternal(request, response, chain)
            assertThat(response.status).isNotEqualTo(429)
        }
    }

    @Test
    fun `returns 429 when limit exceeded`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = true, requestsPerMinute = 2), objectMapper)
        val chain = FilterChain { _, _ -> }

        // Consume both tokens
        repeat(2) {
            filter.doFilterInternal(MockHttpServletRequest(), MockHttpServletResponse(), chain)
        }

        // Third request should be rejected
        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()
        filter.doFilterInternal(request, response, chain)

        assertThat(response.status).isEqualTo(429)
        assertThat(response.contentType).isEqualTo("application/json")
        assertThat(response.contentAsString).contains("RATE_LIMIT_EXCEEDED")
        assertThat(response.getHeader("Retry-After")).isEqualTo("60")
    }

    @Test
    fun `disabled filter passes all requests through`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = false, requestsPerMinute = 1), objectMapper)
        val chain = FilterChain { _, _ -> }

        repeat(10) {
            val request = MockHttpServletRequest()
            val response = MockHttpServletResponse()
            filter.doFilterInternal(request, response, chain)
            assertThat(response.status).isNotEqualTo(429)
        }
    }

    @Test
    fun `uses X-Forwarded-For header when present`() {
        val filter = RateLimitFilter(RateLimitProperties(enabled = true, requestsPerMinute = 1), objectMapper)
        val chain = FilterChain { _, _ -> }

        // First IP gets 1 request
        val req1 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "1.2.3.4") }
        filter.doFilterInternal(req1, MockHttpServletResponse(), chain)

        // Different IP also gets 1 request
        val req2 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "5.6.7.8") }
        val resp2 = MockHttpServletResponse()
        filter.doFilterInternal(req2, resp2, chain)
        assertThat(resp2.status).isNotEqualTo(429)

        // First IP is now exhausted
        val req3 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "1.2.3.4") }
        val resp3 = MockHttpServletResponse()
        filter.doFilterInternal(req3, resp3, chain)
        assertThat(resp3.status).isEqualTo(429)
    }
}
```

### Step 6: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 7: Commit

```bash
git add src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt \
        src/main/kotlin/com/aibles/iam/shared/config/RateLimitProperties.kt \
        src/main/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilter.kt \
        src/main/resources/application.yml \
        src/test/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilterTest.kt
git commit -m "feat(security): add IP-based rate limiting with Bucket4j"
```

---

## Task 2: CORS configuration via properties

**GitHub Issue Title:** `feat(security): add configurable CORS support`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/config/CorsProperties.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Modify: `src/main/resources/application.yml`
- Test: `src/test/kotlin/com/aibles/iam/shared/config/CorsIntegrationTest.kt`

### Step 1: Create CorsProperties

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/CorsProperties.kt
package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "cors")
data class CorsProperties(
    val allowedOrigins: List<String> = listOf("http://localhost:3000"),
    val allowedMethods: List<String> = listOf("GET", "POST", "PATCH", "DELETE", "OPTIONS"),
    val allowedHeaders: List<String> = listOf("Authorization", "Content-Type"),
    val maxAge: Long = 3600,
)
```

### Step 2: Add CORS to SecurityConfig

Update `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`:

```kotlin
package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler
import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(CorsProperties::class)
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val googleOAuth2FailureHandler: GoogleOAuth2FailureHandler,
    private val jwtDecoder: JwtDecoder,
    private val corsProperties: CorsProperties,
) {

    @Bean
    @Order(2)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .cors { it.configurationSource(corsConfigurationSource()) }
            .csrf { it.disable() }
            .headers { headers ->
                headers.frameOptions { it.deny() }
            }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers(
                        "/oauth2/**", "/login/**",
                        "/api/v1/auth/refresh",
                        "/api/v1/auth/logout",
                        "/api/v1/auth/passkey/authenticate/start",
                        "/api/v1/auth/passkey/authenticate/finish",
                        "/actuator/**",
                        "/swagger-ui/**", "/v3/api-docs/**",
                    ).permitAll()
                    .anyRequest().authenticated()
            }
            .oauth2Login {
                it.successHandler(googleOAuth2SuccessHandler)
                it.failureHandler(googleOAuth2FailureHandler)
            }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(jwtDecoder) } }
        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val config = CorsConfiguration().apply {
            allowedOrigins = corsProperties.allowedOrigins
            allowedMethods = corsProperties.allowedMethods
            allowedHeaders = corsProperties.allowedHeaders
            maxAge = corsProperties.maxAge
        }
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return source
    }
}
```

**Note on security headers:** Spring Security already adds `X-Content-Type-Options: nosniff` and `Cache-Control` by default. Adding `.headers { headers -> headers.frameOptions { it.deny() } }` ensures `X-Frame-Options: DENY` is explicit.

### Step 3: Add CORS properties to application.yml

Append to `src/main/resources/application.yml`:

```yaml
cors:
  allowed-origins: ${CORS_ALLOWED_ORIGINS:http://localhost:3000}
  allowed-methods: GET,POST,PATCH,DELETE,OPTIONS
  allowed-headers: Authorization,Content-Type
  max-age: 3600
```

**Important:** The `allowed-origins` property is a comma-separated string. Spring Boot automatically splits it into a `List<String>`.

### Step 4: Write the test

This tests CORS headers using `@WebMvcTest`:

```kotlin
// src/test/kotlin/com/aibles/iam/shared/config/CorsIntegrationTest.kt
package com.aibles.iam.shared.config

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
import com.ninjasquad.springmockk.MockkBean
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.options

@WebMvcTest
@Import(GlobalExceptionHandler::class)
@AutoConfigureMockMvc(addFilters = false)
@TestPropertySource(properties = ["cors.allowed-origins=http://localhost:3000"])
class CorsIntegrationTest {

    @Autowired lateinit var mockMvc: MockMvc

    // All @MockkBean declarations required by @WebMvcTest
    @MockkBean lateinit var queryAuditLogsUseCase: QueryAuditLogsUseCase
    @MockkBean lateinit var recordAuditEventUseCase: RecordAuditEventUseCase
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase
    @MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
    @MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
    @MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
    @MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
    @MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase
    @MockkBean lateinit var passkeyCredentialRepository: PasskeyCredentialRepository

    @Test
    fun `CORS preflight returns correct headers for allowed origin`() {
        mockMvc.options("/api/v1/users") {
            header("Origin", "http://localhost:3000")
            header("Access-Control-Request-Method", "POST")
            header("Access-Control-Request-Headers", "Authorization,Content-Type")
        }.andExpect {
            header { string("Access-Control-Allow-Origin", "http://localhost:3000") }
        }
    }
}
```

**Note:** With `addFilters = false`, the Spring Security filter chain (including CORS) is bypassed. If this doesn't work, remove `addFilters = false` and the test will need full security context. The implementer should try both approaches — if the CORS headers don't appear with `addFilters = false`, switch to including filters and use a permitAll endpoint for the OPTIONS preflight test.

**Alternative approach if `addFilters = false` prevents CORS headers:** Remove `@AutoConfigureMockMvc(addFilters = false)` and test against a permitAll endpoint:

```kotlin
@WebMvcTest
@Import(GlobalExceptionHandler::class, SecurityConfig::class)
class CorsIntegrationTest {
    // ... same mocks ...

    @Test
    fun `CORS preflight returns correct headers for allowed origin`() {
        mockMvc.options("/actuator/health") {
            header("Origin", "http://localhost:3000")
            header("Access-Control-Request-Method", "GET")
        }.andExpect {
            header { string("Access-Control-Allow-Origin", "http://localhost:3000") }
        }
    }
}
```

### Step 5: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 6: Commit

```bash
git add src/main/kotlin/com/aibles/iam/shared/config/CorsProperties.kt \
        src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
        src/main/resources/application.yml \
        src/test/kotlin/com/aibles/iam/shared/config/CorsIntegrationTest.kt
git commit -m "feat(security): add configurable CORS support"
```

---

## Task 3: OpenAPI configuration with controller tags

**GitHub Issue Title:** `feat(docs): add OpenAPI configuration and controller tags`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/config/OpenApiConfig.kt`
- Modify: `src/main/kotlin/com/aibles/iam/identity/api/UsersController.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/api/AuthController.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt`
- Modify: `src/main/kotlin/com/aibles/iam/audit/api/AuditLogsController.kt`

### Step 1: Create OpenApiConfig

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/OpenApiConfig.kt
package com.aibles.iam.shared.config

import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Contact
import io.swagger.v3.oas.models.info.Info
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {

    @Bean
    fun openAPI(): OpenAPI = OpenAPI().info(
        Info()
            .title("IAM Service API")
            .description("Identity & Access Management — Google OAuth2, Passkey/WebAuthn, OAuth2/OIDC SSO, Audit Logging")
            .version("1.0.0")
            .contact(Contact().name("Aibles").url("https://aibles.com"))
    )
}
```

### Step 2: Add `@Tag` to each controller

**UsersController** — add import and annotation:
```kotlin
import io.swagger.v3.oas.annotations.tags.Tag

@RestController
@RequestMapping("/api/v1/users")
@Tag(name = "Users", description = "User lifecycle management")
class UsersController(
```

**AuthController:**
```kotlin
import io.swagger.v3.oas.annotations.tags.Tag

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Auth", description = "Token refresh and logout")
class AuthController(
```

**PasskeyController:**
```kotlin
import io.swagger.v3.oas.annotations.tags.Tag

@RestController
@RequestMapping("/api/v1/auth/passkey")
@Tag(name = "Passkey", description = "WebAuthn passkey registration and authentication")
class PasskeyController(
```

**AuditLogsController:**
```kotlin
import io.swagger.v3.oas.annotations.tags.Tag

@RestController
@RequestMapping("/api/v1/audit-logs")
@Tag(name = "Audit Logs", description = "Query audit trail")
class AuditLogsController(
```

### Step 3: Run tests

Run: `./gradlew test`
Expected: all tests PASS (annotations don't affect test behavior)

### Step 4: Commit

```bash
git add src/main/kotlin/com/aibles/iam/shared/config/OpenApiConfig.kt \
        src/main/kotlin/com/aibles/iam/identity/api/UsersController.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/AuthController.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt \
        src/main/kotlin/com/aibles/iam/audit/api/AuditLogsController.kt
git commit -m "feat(docs): add OpenAPI configuration and controller tags"
```

---

## Task 4: Base integration test with Testcontainers

**GitHub Issue Title:** `test(infra): create BaseIntegrationTest with Testcontainers PostgreSQL and Redis`

**Files:**
- Create: `src/test/kotlin/com/aibles/iam/BaseIntegrationTest.kt`
- Create: `src/test/resources/application-integration.yml`

### Step 1: Create application-integration.yml

Integration tests need specific config overrides:

```yaml
# src/test/resources/application-integration.yml
spring:
  jpa:
    hibernate:
      ddl-auto: validate
    open-in-view: false
  flyway:
    enabled: true
    locations: classpath:db/migration
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: test-client-id
            client-secret: test-client-secret
            scope: openid,email,profile
jwt:
  private-key: ""
  public-key: ""
  access-token-ttl-minutes: 15
webauthn:
  rp-id: localhost
  rp-origin: http://localhost:8080
  rp-name: IAM Service Test
oauth2:
  clients:
    iam-web:
      redirect-uri: http://localhost:3000/callback
    iam-service:
      client-secret: "{noop}test-secret"
rate-limit:
  enabled: false
```

### Step 2: Create BaseIntegrationTest

```kotlin
// src/test/kotlin/com/aibles/iam/BaseIntegrationTest.kt
package com.aibles.iam

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("integration")
abstract class BaseIntegrationTest {

    companion object {
        @Container
        @JvmStatic
        val postgres: PostgreSQLContainer<*> = PostgreSQLContainer("postgres:16-alpine")
            .withDatabaseName("iam_test")
            .withUsername("test")
            .withPassword("test")

        @Container
        @JvmStatic
        val redis: GenericContainer<*> = GenericContainer("redis:7-alpine")
            .withExposedPorts(6379)

        @DynamicPropertySource
        @JvmStatic
        fun configureProperties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url") { postgres.jdbcUrl }
            registry.add("spring.datasource.username") { postgres.username }
            registry.add("spring.datasource.password") { postgres.password }
            registry.add("spring.data.redis.host") { redis.host }
            registry.add("spring.data.redis.port") { redis.getMappedPort(6379) }
        }
    }
}
```

### Step 3: Run tests

Run: `./gradlew test`
Expected: all tests PASS (the base class has no test methods itself, but Spring context loads)

### Step 4: Commit

```bash
git add src/test/kotlin/com/aibles/iam/BaseIntegrationTest.kt \
        src/test/resources/application-integration.yml
git commit -m "test(infra): create BaseIntegrationTest with Testcontainers PostgreSQL and Redis"
```

---

## Task 5: User CRUD integration test

**GitHub Issue Title:** `test(identity): add User CRUD integration test`

**Files:**
- Create: `src/test/kotlin/com/aibles/iam/identity/UserCrudIntegrationTest.kt`

### Step 1: Write the integration test

```kotlin
// src/test/kotlin/com/aibles/iam/identity/UserCrudIntegrationTest.kt
package com.aibles.iam.identity

import com.aibles.iam.BaseIntegrationTest
import com.aibles.iam.identity.api.dto.CreateUserRequest
import com.aibles.iam.identity.api.dto.UpdateUserRequest
import com.aibles.iam.identity.api.dto.ChangeStatusRequest
import com.aibles.iam.identity.domain.user.UserStatus
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.delete
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.patch
import org.springframework.test.web.servlet.post

class UserCrudIntegrationTest : BaseIntegrationTest() {

    @Autowired lateinit var mockMvc: MockMvc
    @Autowired lateinit var objectMapper: ObjectMapper

    @Test
    fun `full user lifecycle - create, read, update, change status, delete`() {
        // CREATE
        val createBody = objectMapper.writeValueAsString(CreateUserRequest("inttest@example.com", "Test User"))
        val createResult = mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = createBody
        }.andExpect {
            status { isCreated() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.email") { value("inttest@example.com") }
            jsonPath("$.data.displayName") { value("Test User") }
            jsonPath("$.data.status") { value("ACTIVE") }
        }.andReturn()

        val userId = objectMapper.readTree(createResult.response.contentAsString)
            .at("/data/id").asText()

        // READ
        mockMvc.get("/api/v1/users/$userId") {
            with(jwt())
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.email") { value("inttest@example.com") }
        }

        // UPDATE
        val updateBody = objectMapper.writeValueAsString(UpdateUserRequest("Updated Name"))
        mockMvc.patch("/api/v1/users/$userId") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = updateBody
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.displayName") { value("Updated Name") }
        }

        // CHANGE STATUS
        val statusBody = objectMapper.writeValueAsString(ChangeStatusRequest(UserStatus.DISABLED))
        mockMvc.patch("/api/v1/users/$userId/status") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = statusBody
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.status") { value("DISABLED") }
        }

        // DELETE
        mockMvc.delete("/api/v1/users/$userId") {
            with(jwt())
        }.andExpect {
            status { isNoContent() }
        }

        // VERIFY DELETED
        mockMvc.get("/api/v1/users/$userId") {
            with(jwt())
        }.andExpect {
            status { isNotFound() }
        }
    }

    @Test
    fun `create user with duplicate email returns 409`() {
        val body = objectMapper.writeValueAsString(CreateUserRequest("duplicate@example.com", null))
        mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect { status { isCreated() } }

        mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect {
            status { isConflict() }
            jsonPath("$.error.code") { value("USER_EMAIL_CONFLICT") }
        }
    }
}
```

### Step 2: Run tests

Run: `./gradlew test`
Expected: all tests PASS. Testcontainers starts PostgreSQL + Redis, Flyway migrates, Spring context loads, and the full user lifecycle works end-to-end.

### Step 3: Commit

```bash
git add src/test/kotlin/com/aibles/iam/identity/UserCrudIntegrationTest.kt
git commit -m "test(identity): add User CRUD integration test"
```

---

## Task 6: Audit log query integration test

**GitHub Issue Title:** `test(audit): add audit log query integration test`

**Files:**
- Create: `src/test/kotlin/com/aibles/iam/audit/AuditLogIntegrationTest.kt`

### Step 1: Write the integration test

```kotlin
// src/test/kotlin/com/aibles/iam/audit/AuditLogIntegrationTest.kt
package com.aibles.iam.audit

import com.aibles.iam.BaseIntegrationTest
import com.aibles.iam.identity.api.dto.CreateUserRequest
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post

class AuditLogIntegrationTest : BaseIntegrationTest() {

    @Autowired lateinit var mockMvc: MockMvc
    @Autowired lateinit var objectMapper: ObjectMapper

    @Test
    fun `creating a user produces USER_CREATED audit event`() {
        val body = objectMapper.writeValueAsString(
            CreateUserRequest("audit-test@example.com", "Audit Test")
        )

        // Create a user — this should trigger a USER_CREATED audit event
        mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect { status { isCreated() } }

        // Query audit logs for USER_CREATED events
        mockMvc.get("/api/v1/audit-logs") {
            with(jwt())
            param("eventType", "USER_CREATED")
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.totalElements") { value(1) }
            jsonPath("$.data.content[0].eventType") { value("USER_CREATED") }
            jsonPath("$.data.content[0].metadata.email") { value("audit-test@example.com") }
        }
    }

    @Test
    fun `audit-logs endpoint returns empty page when no events`() {
        mockMvc.get("/api/v1/audit-logs") {
            with(jwt())
            param("eventType", "TOKEN_REVOKED")
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.totalElements") { value(0) }
            jsonPath("$.data.content") { isEmpty() }
        }
    }
}
```

**Note:** The `totalElements` assertion in test 1 might be > 1 if the `UserCrudIntegrationTest` ran first and shared the same Testcontainers database. If tests share the same `@SpringBootTest` context, the database accumulates data. Two approaches:
1. Use `@DirtiesContext` to restart context per test class (slower).
2. Use `@Transactional` on the test class to rollback after each test.
3. Accept that `totalElements >= 1` and use `jsonPath("$.data.content[?(@.metadata.email == 'audit-test@example.com')]")`.

The simplest fix: use `@Transactional` on the test class or use a more lenient assertion. The implementer should adjust the assertion if needed.

### Step 2: Run tests

Run: `./gradlew test`
Expected: all tests PASS

### Step 3: Commit

```bash
git add src/test/kotlin/com/aibles/iam/audit/AuditLogIntegrationTest.kt
git commit -m "test(audit): add audit log query integration test"
```

---

## Summary

| Task | Type | Description |
|------|------|-------------|
| 1 | feat | IP-based rate limiting with Bucket4j + `RATE_LIMIT_EXCEEDED` error code |
| 2 | feat | Configurable CORS via properties + security headers (`X-Frame-Options: DENY`) |
| 3 | feat | OpenAPI config bean + `@Tag` on all 4 controllers |
| 4 | test | `BaseIntegrationTest` with Testcontainers PostgreSQL + Redis |
| 5 | test | User CRUD lifecycle integration test |
| 6 | test | Audit log query integration test (verifies cross-BC event pipeline) |
