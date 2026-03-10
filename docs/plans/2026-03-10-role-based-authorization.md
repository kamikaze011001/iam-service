# Role-Based Authorization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enforce ADMIN-only access to user-management and audit-log APIs so that normal users (ROLE_USER) from Google OAuth2 or passkey login cannot reach those endpoints.

**Architecture:** JWT tokens already carry a `roles` claim (e.g. `["USER"]`) written by `IssueTokenUseCase` → `JwtService`. Three gaps must be closed: (1) Spring Security's default JWT converter ignores the `roles` claim, so every authenticated user has zero authorities; (2) no URL rules protect `/api/v1/users/**` or `/api/v1/audit-logs/**`; (3) Spring Security's 401/403 error responses use its own JSON format instead of `ApiResponse`. A stale `users.roles TEXT[]` column that JPA never maintains is also dropped.

**Tech Stack:** Spring Security 6.x, Spring Boot 3.4.x, Kotlin 2.x, `spring-security-test` (already in `build.gradle.kts`), SpringMockK, JUnit 5.

---

### Task 1: Wire JWT `roles` claim to Spring Security `GrantedAuthority`

**Context:**
`JwtService.generateAccessToken()` writes `claim("roles", roles.toList())` in every JWT. Spring Security's built-in `JwtGrantedAuthoritiesConverter` only reads `scope`/`scp` claims. So even with `roles: ["USER"]` in the token, Spring Security sees an empty authority set and `hasRole("ADMIN")` always fails.

We expose a static factory function `SecurityConfig.buildRolesConverter()` (testable without starting Spring), wire it into the `oauth2ResourceServer` block, and add `@EnableMethodSecurity` for future `@PreAuthorize` use.

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Create: `src/test/kotlin/com/aibles/iam/shared/config/JwtRolesConverterTest.kt`

**Step 1: Write the failing test**

```kotlin
// src/test/kotlin/com/aibles/iam/shared/config/JwtRolesConverterTest.kt
package com.aibles.iam.shared.config

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.jwt.Jwt

class JwtRolesConverterTest {

    private val converter = SecurityConfig.buildRolesConverter()

    @Test
    fun `converts roles claim to ROLE_ prefixed authorities`() {
        val jwt = Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("user-1")
            .claim("roles", listOf("USER", "ADMIN"))
            .build()
        val authorities = converter.convert(jwt)
        assertThat(authorities!!.map { it.authority })
            .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN")
    }

    @Test
    fun `returns empty list when roles claim is absent`() {
        val jwt = Jwt.withTokenValue("token")
            .header("alg", "RS256")
            .subject("user-1")
            .build()
        val authorities = converter.convert(jwt)
        assertThat(authorities).isEmpty()
    }
}
```

**Step 2: Run test to verify it fails**

```bash
cd /mnt/526a4d3a-8fab-4308-8259-76d6cbf0b318/AIBLES/iam-service/.worktrees/role-based-authorization
./gradlew test --tests "com.aibles.iam.shared.config.JwtRolesConverterTest" -x jacocoTestReport
```
Expected: FAIL — `SecurityConfig.buildRolesConverter()` does not exist yet.

**Step 3: Implement**

Modify `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`:

1. Add `@EnableMethodSecurity` annotation on the class:
```kotlin
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(CorsProperties::class)
class SecurityConfig(...)
```

2. Add new imports:
```kotlin
import org.springframework.core.convert.converter.Converter
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
```

3. Add companion object inside `SecurityConfig` class:
```kotlin
companion object {
    fun buildRolesConverter(): Converter<Jwt, Collection<GrantedAuthority>> = Converter { jwt ->
        (jwt.getClaimAsStringList("roles") ?: emptyList())
            .map { SimpleGrantedAuthority("ROLE_$it") }
    }
}
```

4. Replace the `oauth2ResourceServer` line in `securityFilterChain()`:
```kotlin
// BEFORE:
.oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(jwtDecoder) } }

// AFTER:
.oauth2ResourceServer {
    it.jwt { jwt ->
        jwt.decoder(jwtDecoder)
        jwt.jwtAuthenticationConverter(
            JwtAuthenticationConverter().also { c ->
                c.setJwtGrantedAuthoritiesConverter(buildRolesConverter())
            }
        )
    }
}
```

**Step 4: Run test to verify it passes**

```bash
./gradlew test --tests "com.aibles.iam.shared.config.JwtRolesConverterTest" -x jacocoTestReport
```
Expected: PASS

**Step 5: Run all tests**

```bash
./gradlew test -x jacocoTestReport
```
Expected: all 159+ tests pass.

**Step 6: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
        src/test/kotlin/com/aibles/iam/shared/config/JwtRolesConverterTest.kt
git commit -m "feat: wire JWT roles claim to Spring Security authorities + enable method security"
```

---

### Task 2: Restrict admin routes to ROLE_ADMIN via URL rules

**Context:**
`/api/v1/users/**` and `/api/v1/audit-logs/**` are administration APIs. They must only be reachable by users whose JWT contains `"ADMIN"` in the `roles` claim (maps to `ROLE_ADMIN` after Task 1). We add one rule to `authorizeHttpRequests` and write a dedicated security test that activates the real filter chain (no `addFilters = false`).

Note: The test uses `SecurityMockMvcRequestPostProcessors.jwt()` which bypasses JWT decoding and injects the `Authentication` directly — no real RSA keys or JwtDecoder needed for the check itself. The existing controller tests use `@AutoConfigureMockMvc(addFilters = false)` and are unaffected.

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Create: `src/test/kotlin/com/aibles/iam/shared/security/AdminRouteSecurityTest.kt`

**Step 1: Write the failing tests**

```kotlin
// src/test/kotlin/com/aibles/iam/shared/security/AdminRouteSecurityTest.kt
package com.aibles.iam.shared.security

import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.audit.usecase.RecordAuditEventUseCase
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler
import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.FinishRegistrationUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
import com.aibles.iam.authentication.usecase.SendPasskeyOtpUseCase
import com.aibles.iam.authentication.usecase.SendRegistrationOtpUseCase
import com.aibles.iam.authentication.usecase.StartRegistrationUseCase
import com.aibles.iam.authentication.usecase.VerifyPasskeyOtpUseCase
import com.aibles.iam.authentication.usecase.VerifyRegistrationOtpUseCase
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.ChangeUserStatusUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.identity.usecase.DeleteUserUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.identity.usecase.UpdateUserUseCase
import com.aibles.iam.shared.config.SecurityConfig
import com.aibles.iam.shared.error.GlobalExceptionHandler
import com.aibles.iam.shared.web.HttpContextExtractor
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.util.UUID

@WebMvcTest
@Import(SecurityConfig::class, GlobalExceptionHandler::class)
@TestPropertySource(properties = [
    "cors.allowed-origins=http://localhost:3000",
    "cors.allowed-methods=GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "cors.allowed-headers=*",
    "cors.max-age=3600",
])
class AdminRouteSecurityTest {

    @Autowired lateinit var mockMvc: MockMvc

    // SecurityConfig constructor deps
    @MockkBean lateinit var googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler
    @MockkBean lateinit var googleOAuth2FailureHandler: GoogleOAuth2FailureHandler
    @MockkBean lateinit var jwtDecoder: JwtDecoder

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
    @MockkBean lateinit var sendPasskeyOtpUseCase: SendPasskeyOtpUseCase
    @MockkBean lateinit var verifyPasskeyOtpUseCase: VerifyPasskeyOtpUseCase

    // RegisterController deps
    @MockkBean lateinit var sendRegistrationOtpUseCase: SendRegistrationOtpUseCase
    @MockkBean lateinit var verifyRegistrationOtpUseCase: VerifyRegistrationOtpUseCase
    @MockkBean lateinit var startRegistrationUseCase: StartRegistrationUseCase
    @MockkBean lateinit var finishRegistrationUseCase: FinishRegistrationUseCase

    // AuditLogsController deps
    @MockkBean lateinit var queryAuditLogsUseCase: QueryAuditLogsUseCase
    @MockkBean lateinit var recordAuditEventUseCase: RecordAuditEventUseCase

    // Shared
    @MockkBean lateinit var httpContextExtractor: HttpContextExtractor

    private val testUser = User.create("admin@example.com", "Admin")

    @Test
    fun `ROLE_USER cannot GET users - receives 403`() {
        mockMvc.get("/api/v1/users/${UUID.randomUUID()}")
            .with(jwt().authorities(SimpleGrantedAuthority("ROLE_USER")))
            .andExpect { status { isForbidden() } }
    }

    @Test
    fun `ROLE_ADMIN can GET users`() {
        every { getUserUseCase.execute(any()) } returns testUser
        mockMvc.get("/api/v1/users/${testUser.id}")
            .with(jwt().authorities(SimpleGrantedAuthority("ROLE_ADMIN")))
            .andExpect { status { isOk() } }
    }

    @Test
    fun `unauthenticated request to admin route receives 401`() {
        mockMvc.get("/api/v1/users/${UUID.randomUUID()}")
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `ROLE_USER cannot GET audit-logs - receives 403`() {
        mockMvc.get("/api/v1/audit-logs")
            .with(jwt().authorities(SimpleGrantedAuthority("ROLE_USER")))
            .andExpect { status { isForbidden() } }
    }

    @Test
    fun `ROLE_ADMIN can GET audit-logs`() {
        every { queryAuditLogsUseCase.execute(any()) } returns QueryAuditLogsUseCase.Result(
            content = emptyList(), page = 0, size = 20, totalElements = 0L, totalPages = 0
        )
        mockMvc.get("/api/v1/audit-logs")
            .with(jwt().authorities(SimpleGrantedAuthority("ROLE_ADMIN")))
            .andExpect { status { isOk() } }
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
./gradlew test --tests "com.aibles.iam.shared.security.AdminRouteSecurityTest" -x jacocoTestReport
```
Expected: FAIL — `ROLE_USER cannot GET users` gets 200 instead of 403.

**Step 3: Add admin URL rule to SecurityConfig**

In `securityFilterChain()`, add ONE line inside `authorizeHttpRequests` BEFORE `.anyRequest().authenticated()`:

```kotlin
.authorizeHttpRequests { auth ->
    auth
        .requestMatchers(
            "/oauth2/**", "/login/**",
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            "/api/v1/auth/passkey/authenticate/start",
            "/api/v1/auth/passkey/authenticate/finish",
            "/api/v1/auth/register/**",
            "/actuator/health", "/actuator/info",
            "/swagger-ui/**", "/v3/api-docs/**",
        ).permitAll()
        .requestMatchers("/api/v1/users/**", "/api/v1/audit-logs/**").hasRole("ADMIN")  // ← ADD
        .anyRequest().authenticated()
}
```

**Step 4: Run tests to verify they pass**

```bash
./gradlew test --tests "com.aibles.iam.shared.security.AdminRouteSecurityTest" -x jacocoTestReport
```
Expected: all 5 tests PASS.

**Step 5: Run all tests**

```bash
./gradlew test -x jacocoTestReport
```
Expected: all pass.

**Step 6: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
        src/test/kotlin/com/aibles/iam/shared/security/AdminRouteSecurityTest.kt
git commit -m "feat: restrict /api/v1/users/** and /api/v1/audit-logs/** to ROLE_ADMIN"
```

---

### Task 3: Return `ApiResponse` format for Spring Security 401 and 403 errors

**Context:**
When Spring Security rejects a request (no token → 401, wrong role → 403) it produces its own JSON:
`{"timestamp":"...","status":403,"error":"Forbidden","path":"..."}`.
The frontend expects the uniform `ApiResponse` envelope:
`{"success":false,"data":null,"error":{"code":"FORBIDDEN","message":"..."},"timestamp":"..."}`.

We add two `@Component` handlers and wire them into `SecurityConfig`.

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/security/ApiAuthEntryPoint.kt`
- Create: `src/main/kotlin/com/aibles/iam/shared/security/ApiAccessDeniedHandler.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Modify: `src/test/kotlin/com/aibles/iam/shared/security/AdminRouteSecurityTest.kt`

**Step 1: Add two failing tests to `AdminRouteSecurityTest`**

Add these tests to the existing class (do NOT rewrite the whole class — just append):

```kotlin
@Test
fun `unauthenticated request returns ApiResponse body with UNAUTHORIZED code`() {
    mockMvc.get("/api/v1/users/${UUID.randomUUID()}")
        .andExpect {
            status { isUnauthorized() }
            jsonPath("$.success") { value(false) }
            jsonPath("$.error.code") { value("UNAUTHORIZED") }
        }
}

@Test
fun `ROLE_USER on admin route returns ApiResponse body with FORBIDDEN code`() {
    mockMvc.get("/api/v1/users/${UUID.randomUUID()}")
        .with(jwt().authorities(SimpleGrantedAuthority("ROLE_USER")))
        .andExpect {
            status { isForbidden() }
            jsonPath("$.success") { value(false) }
            jsonPath("$.error.code") { value("FORBIDDEN") }
        }
}
```

**Step 2: Run the two new tests to verify they fail**

```bash
./gradlew test --tests "com.aibles.iam.shared.security.AdminRouteSecurityTest" -x jacocoTestReport
```
Expected: the 2 new tests FAIL (body is Spring's default format, not ApiResponse).

**Step 3: Create `ApiAuthEntryPoint.kt`**

```kotlin
// src/main/kotlin/com/aibles/iam/shared/security/ApiAuthEntryPoint.kt
package com.aibles.iam.shared.security

import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component

@Component
class ApiAuthEntryPoint(private val objectMapper: ObjectMapper) : AuthenticationEntryPoint {
    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException,
    ) {
        response.status = 401
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(response.writer, ApiResponse.error("UNAUTHORIZED", "Authentication required"))
    }
}
```

**Step 4: Create `ApiAccessDeniedHandler.kt`**

```kotlin
// src/main/kotlin/com/aibles/iam/shared/security/ApiAccessDeniedHandler.kt
package com.aibles.iam.shared.security

import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.stereotype.Component

@Component
class ApiAccessDeniedHandler(private val objectMapper: ObjectMapper) : AccessDeniedHandler {
    override fun handle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        accessDeniedException: AccessDeniedException,
    ) {
        response.status = 403
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(response.writer, ApiResponse.error("FORBIDDEN", "Access denied"))
    }
}
```

**Step 5: Wire into SecurityConfig**

Add both to `SecurityConfig`'s constructor (add after `corsProperties`):
```kotlin
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val googleOAuth2FailureHandler: GoogleOAuth2FailureHandler,
    private val jwtDecoder: JwtDecoder,
    private val corsProperties: CorsProperties,
    private val apiAuthEntryPoint: ApiAuthEntryPoint,
    private val apiAccessDeniedHandler: ApiAccessDeniedHandler,
)
```

Add imports:
```kotlin
import com.aibles.iam.shared.security.ApiAuthEntryPoint
import com.aibles.iam.shared.security.ApiAccessDeniedHandler
```

Add `.exceptionHandling` block inside `securityFilterChain()` after the `.oauth2ResourceServer` block:
```kotlin
.exceptionHandling {
    it.authenticationEntryPoint(apiAuthEntryPoint)
    it.accessDeniedHandler(apiAccessDeniedHandler)
}
```

**Step 6: Update `@Import` in `AdminRouteSecurityTest`**

Change the `@Import` line to include the two real beans:
```kotlin
@Import(SecurityConfig::class, GlobalExceptionHandler::class,
        ApiAuthEntryPoint::class, ApiAccessDeniedHandler::class)
```

Also add `SecurityConfig`'s new constructor deps as `@MockkBean` (they're already `@MockkBean` — no new mocks needed, the handlers are real beans via `@Import`).

**Step 7: Run all security tests**

```bash
./gradlew test --tests "com.aibles.iam.shared.security.AdminRouteSecurityTest" -x jacocoTestReport
```
Expected: all 7 tests PASS.

**Step 8: Run all tests**

```bash
./gradlew test -x jacocoTestReport
```
Expected: all pass.

**Step 9: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/security/ApiAuthEntryPoint.kt \
        src/main/kotlin/com/aibles/iam/shared/security/ApiAccessDeniedHandler.kt \
        src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
        src/test/kotlin/com/aibles/iam/shared/security/AdminRouteSecurityTest.kt
git commit -m "feat: return ApiResponse format for Spring Security 401/403 errors"
```

---

### Task 4: Flyway migration — drop stale `users.roles TEXT[]` column

**Context:**
`V1__init_schema.sql` created `users.roles TEXT[] NOT NULL DEFAULT '{USER}'`. The `User` entity maps roles via `@ElementCollection` → `user_roles` join table. JPA never reads or writes `users.roles`; it always stays at `{USER}` regardless of what roles are in `user_roles`. Drop it to eliminate misleading data.

**Files:**
- Create: `src/main/resources/db/migration/V5__drop_stale_roles_column.sql`

**Step 1: Create the migration**

```sql
-- V5__drop_stale_roles_column.sql
-- users.roles TEXT[] was created in V1 but is never maintained by JPA.
-- Role data lives exclusively in the user_roles join table (@ElementCollection on User.roles).
ALTER TABLE users DROP COLUMN roles;
```

**Step 2: Run all tests (Flyway validates the migration)**

```bash
./gradlew test -x jacocoTestReport
```
Testcontainers spins up PostgreSQL and runs all migrations including V5. Expected: all pass.

**Step 3: Commit**

```bash
git add src/main/resources/db/migration/V5__drop_stale_roles_column.sql
git commit -m "chore: drop stale users.roles TEXT[] column (superseded by user_roles join table)"
```

---

## Bootstrap: Promoting the first ADMIN user

No API exists to assign `ROLE_ADMIN`. Bootstrap via direct SQL:

```sql
-- 1. Find the user to promote
SELECT id, email FROM users WHERE email = 'your-admin@example.com';

-- 2. Grant ADMIN role (USER already exists from registration)
INSERT INTO user_roles (user_id, role)
VALUES ('<uuid-from-step-1>', 'ADMIN')
ON CONFLICT DO NOTHING;
```

Their **next login** will issue a JWT with `roles: ["USER", "ADMIN"]`, granting access to admin routes.
