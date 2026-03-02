# Sprint 5: OAuth2/OIDC Authorization Server Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Expose a Spring Authorization Server (1.4.2) that issues standards-compliant OAuth2/OIDC tokens, backed by PostgreSQL, reusing the existing RS256 key pair.

**Architecture:** Two ordered `SecurityFilterChain` beans — an AS chain (`@Order(HIGHEST_PRECEDENCE)`) handling `/oauth2/**` and `/.well-known/**`, and the existing API chain (`@Order(2)`) staying a JWT resource server. A shared `JWKSource` bean (in `AuthorizationServerConfig`) decodes the RSA key pair from `JwtProperties` so both chains validate the same tokens. Registered clients and authorizations are JDBC-persisted to PostgreSQL. `GoogleOAuth2SuccessHandler` is updated to detect the AS authorization flow (via `HttpSessionRequestCache`) and redirect back to the AS instead of writing a token JSON response. An `ApplicationRunner` seeds the default clients on startup.

**Tech Stack:** Spring Authorization Server 1.4.2 (already in `build.gradle.kts`), Spring Security 6.x, Spring Data JDBC (`JdbcTemplate`), PostgreSQL 16, Flyway, JUnit 5 + MockK + Testcontainers

---

## Context for the Implementer

### Current state before Sprint 5

- `SecurityConfig.kt` — single `SecurityFilterChain`, no `@Order`, owns a `@Bean fun jwtDecoder()` (decode-only, from `JwtProperties.publicKey`)
- `JwtService.kt` — `@Component`, creates its own private `NimbusJwtEncoder`/`NimbusJwtDecoder` using the full key pair; NOT exposed as Spring beans
- `JwtProperties.kt` — `privateKey`, `publicKey` (Base64 PKCS#8/X.509 DER), `accessTokenTtlMinutes`
- `GoogleOAuth2SuccessHandler.kt` — on Google OAuth2 success, always writes a JSON token response directly to `HttpServletResponse`
- Database — only V1 migration exists; no OAuth2 AS tables yet
- `UserRepository.kt` — has `findByEmail(email)` and `findByGoogleSub(googleSub)`

### Key constraint: avoiding a `JwtDecoder` bean conflict

`SecurityConfig` currently declares `@Bean fun jwtDecoder()`. `AuthorizationServerConfig` must also expose a `JwtDecoder` (needed by the AS's `/userinfo` and OIDC validation). Having two `JwtDecoder` beans causes ambiguity. **Solution:** move the single `JwtDecoder` bean to `AuthorizationServerConfig`, remove it from `SecurityConfig`, and inject it into `SecurityConfig` via constructor.

### Why `GoogleOAuth2SuccessHandler` must be updated

When a browser user authorizes a client via the AS (`/oauth2/authorize`), Spring Security stores the original authorization request in the HTTP session. The user is then redirected to Google. On return, `GoogleOAuth2SuccessHandler` currently writes a JSON response, which breaks the AS redirect back to the client. The fix: check `HttpSessionRequestCache` for a saved request. If one exists (AS flow), call `SavedRequestAwareAuthenticationSuccessHandler.onAuthenticationSuccess()` to redirect back. If none (direct Google login flow), behave as before.

---

## Task 1: Database Migration + Authorization Server Core Config (Issue #18)

**Files:**
- Create: `src/main/resources/db/migration/V2__oauth2_schema.sql`
- Create: `src/main/kotlin/com/aibles/iam/authorization/infra/authserver/AuthorizationServerConfig.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`
- Create: `src/test/kotlin/com/aibles/iam/authorization/infra/authserver/AuthorizationServerConfigTest.kt`

---

### Step 1: Write the failing integration test

```kotlin
// src/test/kotlin/com/aibles/iam/authorization/infra/authserver/AuthorizationServerConfigTest.kt
package com.aibles.iam.authorization.infra.authserver

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.DynamicPropertyRegistry
import org.springframework.test.context.DynamicPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.security.KeyPairGenerator
import java.util.Base64

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthorizationServerConfigTest {

    @Autowired lateinit var mockMvc: MockMvc

    companion object {
        @Container @JvmStatic
        val postgres = PostgreSQLContainer<Nothing>("postgres:16-alpine")

        @Container @JvmStatic
        val redis = GenericContainer<Nothing>("redis:7-alpine").withExposedPorts(6379)

        private val keyPair by lazy {
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        }

        @JvmStatic
        @DynamicPropertySource
        fun properties(registry: DynamicPropertyRegistry) {
            registry.add("spring.datasource.url") { postgres.jdbcUrl }
            registry.add("spring.datasource.username") { postgres.username }
            registry.add("spring.datasource.password") { postgres.password }
            registry.add("spring.data.redis.host") { redis.host }
            registry.add("spring.data.redis.port") { redis.getMappedPort(6379).toString() }
            registry.add("jwt.private-key") { Base64.getEncoder().encodeToString(keyPair.private.encoded) }
            registry.add("jwt.public-key") { Base64.getEncoder().encodeToString(keyPair.public.encoded) }
        }
    }

    @Test
    fun `OIDC discovery endpoint returns issuer and jwks_uri`() {
        mockMvc.get("/.well-known/openid-configuration")
            .andExpect {
                status { isOk() }
                jsonPath("$.issuer") { exists() }
                jsonPath("$.jwks_uri") { exists() }
                jsonPath("$.token_endpoint") { exists() }
                jsonPath("$.authorization_endpoint") { exists() }
            }
    }

    @Test
    fun `JWK Set endpoint returns RSA key`() {
        mockMvc.get("/oauth2/jwks")
            .andExpect {
                status { isOk() }
                jsonPath("$.keys") { isArray() }
                jsonPath("$.keys[0].kty") { value("RSA") }
                jsonPath("$.keys[0].kid") { value("iam-rsa") }
            }
    }
}
```

### Step 2: Run the test to verify it fails

```bash
source ~/.sdkman/bin/sdkman-init.sh && sdk use java 24.0.2-amzn
./gradlew test --tests "com.aibles.iam.authorization.infra.authserver.AuthorizationServerConfigTest" 2>&1 | tail -30
```

Expected: FAIL — `/.well-known/openid-configuration` returns 404 (no AS configured yet).

---

### Step 3: Create the V2 database migration

```sql
-- src/main/resources/db/migration/V2__oauth2_schema.sql
-- Spring Authorization Server 1.4.x schemas, adapted for PostgreSQL (blob → text)

CREATE TABLE oauth2_registered_client (
    id                            varchar(100)                        NOT NULL,
    client_id                     varchar(100)                        NOT NULL,
    client_id_issued_at           timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret                 varchar(200)                        DEFAULT NULL,
    client_secret_expires_at      timestamp                           DEFAULT NULL,
    client_name                   varchar(200)                        NOT NULL,
    client_authentication_methods varchar(1000)                       NOT NULL,
    authorization_grant_types     varchar(1000)                       NOT NULL,
    redirect_uris                 varchar(1000)                       DEFAULT NULL,
    post_logout_redirect_uris     varchar(1000)                       DEFAULT NULL,
    scopes                        varchar(1000)                       NOT NULL,
    client_settings               varchar(2000)                       NOT NULL,
    token_settings                varchar(2000)                       NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization (
    id                            varchar(100)  NOT NULL,
    registered_client_id          varchar(100)  NOT NULL,
    principal_name                varchar(200)  NOT NULL,
    authorization_grant_type      varchar(100)  NOT NULL,
    authorized_scopes             varchar(1000) DEFAULT NULL,
    attributes                    text          DEFAULT NULL,
    state                         varchar(500)  DEFAULT NULL,
    authorization_code_value      text          DEFAULT NULL,
    authorization_code_issued_at  timestamp     DEFAULT NULL,
    authorization_code_expires_at timestamp     DEFAULT NULL,
    authorization_code_metadata   text          DEFAULT NULL,
    access_token_value            text          DEFAULT NULL,
    access_token_issued_at        timestamp     DEFAULT NULL,
    access_token_expires_at       timestamp     DEFAULT NULL,
    access_token_metadata         text          DEFAULT NULL,
    access_token_type             varchar(100)  DEFAULT NULL,
    access_token_scopes           varchar(1000) DEFAULT NULL,
    oidc_id_token_value           text          DEFAULT NULL,
    oidc_id_token_issued_at       timestamp     DEFAULT NULL,
    oidc_id_token_expires_at      timestamp     DEFAULT NULL,
    oidc_id_token_metadata        text          DEFAULT NULL,
    refresh_token_value           text          DEFAULT NULL,
    refresh_token_issued_at       timestamp     DEFAULT NULL,
    refresh_token_expires_at      timestamp     DEFAULT NULL,
    refresh_token_metadata        text          DEFAULT NULL,
    user_code_value               text          DEFAULT NULL,
    user_code_issued_at           timestamp     DEFAULT NULL,
    user_code_expires_at          timestamp     DEFAULT NULL,
    user_code_metadata            text          DEFAULT NULL,
    device_code_value             text          DEFAULT NULL,
    device_code_issued_at         timestamp     DEFAULT NULL,
    device_code_expires_at        timestamp     DEFAULT NULL,
    device_code_metadata          text          DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100)  NOT NULL,
    principal_name       varchar(200)  NOT NULL,
    authorities          varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
```

---

### Step 4: Create `AuthorizationServerConfig`

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/infra/authserver/AuthorizationServerConfig.kt
package com.aibles.iam.authorization.infra.authserver

import com.aibles.iam.shared.config.JwtProperties
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.consent.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.consent.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.sql.DataSource

@Configuration
class AuthorizationServerConfig(private val jwtProperties: JwtProperties) {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authorizationServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val configurer = OAuth2AuthorizationServerConfigurer()
        http
            .securityMatcher(configurer.endpointsMatcher)
            .with(configurer) { it.oidc(Customizer.withDefaults()) }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .exceptionHandling {
                it.defaultAuthenticationEntryPointFor(
                    LoginUrlAuthenticationEntryPoint("/oauth2/authorization/google"),
                    MediaTypeRequestMatcher(MediaType.TEXT_HTML),
                )
            }
        return http.build()
    }

    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val kf = KeyFactory.getInstance("RSA")
        val privateKey = kf.generatePrivate(
            PKCS8EncodedKeySpec(Base64.getDecoder().decode(jwtProperties.privateKey))
        ) as RSAPrivateKey
        val publicKey = kf.generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(jwtProperties.publicKey))
        ) as RSAPublicKey
        val rsaKey = RSAKey.Builder(publicKey).privateKey(privateKey).keyID("iam-rsa").build()
        return ImmutableJWKSet(JWKSet(rsaKey))
    }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().build()

    @Bean
    fun registeredClientRepository(dataSource: DataSource): RegisteredClientRepository =
        JdbcRegisteredClientRepository(JdbcTemplate(dataSource))

    @Bean
    fun authorizationService(
        dataSource: DataSource,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationService =
        JdbcOAuth2AuthorizationService(JdbcTemplate(dataSource), registeredClientRepository)

    @Bean
    fun authorizationConsentService(
        dataSource: DataSource,
        registeredClientRepository: RegisteredClientRepository,
    ): OAuth2AuthorizationConsentService =
        JdbcOAuth2AuthorizationConsentService(JdbcTemplate(dataSource), registeredClientRepository)
}
```

---

### Step 5: Update `SecurityConfig`

Remove the `jwtDecoder()` bean (now provided by `AuthorizationServerConfig`). Add `@Order(2)` to the filter chain method. Inject `JwtDecoder` via constructor. Remove `jwtProperties` constructor parameter (no longer needed here). Remove `generateTestKey()` helper.

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt
package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
    private val jwtDecoder: JwtDecoder,
) {

    @Bean
    @Order(2)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
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
            .oauth2Login { it.successHandler(googleOAuth2SuccessHandler) }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(jwtDecoder) } }
        return http.build()
    }
}
```

---

### Step 6: Update `GoogleOAuth2SuccessHandler`

Detect the AS authorization code flow by checking for a saved request in the `HttpSessionRequestCache`. If found, redirect back to the AS; otherwise write the token JSON as before.

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt
package com.aibles.iam.authentication.infra

import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2SuccessHandler(
    private val loginWithGoogleUseCase: LoginWithGoogleUseCase,
    private val objectMapper: ObjectMapper,
) : AuthenticationSuccessHandler {

    private val requestCache = HttpSessionRequestCache()
    private val savedRequestHandler = SavedRequestAwareAuthenticationSuccessHandler()

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val principal = authentication.principal
        if (principal !is OidcUser) {
            response.status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR
            response.contentType = MediaType.APPLICATION_JSON_VALUE
            objectMapper.writeValue(
                response.writer,
                ApiResponse.error("INTERNAL_ERROR", "Unexpected authentication principal type")
            )
            return
        }

        // Ensure user exists in DB for both flows
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))

        // OAuth2 AS authorization code flow: a saved request exists in the session.
        // Redirect back so the AS can issue the authorization code to the client.
        val savedRequest = requestCache.getRequest(request, response)
        if (savedRequest != null) {
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication)
            return
        }

        // Direct Google login flow: write token JSON response
        val body = ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpServletResponse.SC_OK
        objectMapper.writeValue(response.writer, body)
    }
}
```

---

### Step 7: Run the failing test — verify it now passes

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.authserver.AuthorizationServerConfigTest" 2>&1 | tail -30
```

Expected: PASS — both `/.well-known/openid-configuration` and `/oauth2/jwks` return 200.

### Step 8: Run the full test suite

```bash
./gradlew test 2>&1 | tail -20
```

Expected: `BUILD SUCCESSFUL` — all existing tests still pass.

### Step 9: Commit

```bash
git add \
  src/main/resources/db/migration/V2__oauth2_schema.sql \
  src/main/kotlin/com/aibles/iam/authorization/infra/authserver/AuthorizationServerConfig.kt \
  src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
  src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt \
  src/test/kotlin/com/aibles/iam/authorization/infra/authserver/AuthorizationServerConfigTest.kt
git commit -m "feat(authorization): Spring Authorization Server config + V2 schema migration (Closes #<issue-18-number>)"
```

Then push, create PR, squash merge, delete branch, pull main.

---

## Task 2: OIDC Token Customizer (Issue #19)

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authorization/infra/authserver/OidcTokenCustomizer.kt`
- Create: `src/test/kotlin/com/aibles/iam/authorization/infra/authserver/OidcTokenCustomizerTest.kt`

**Context:** The `OAuth2TokenCustomizer<JwtEncodingContext>` bean is auto-detected by Spring Authorization Server and called whenever it encodes a JWT. We gate on `OidcParameterNames.ID_TOKEN` so only the OIDC ID token is enriched (not every access token). The principal in the ID token context is the `OidcUser` from Google OAuth2 login; `authentication.name` is the Google `sub` claim. We use `UserRepository.findByGoogleSub()` to retrieve the user.

---

### Step 1: Write the failing unit test

```kotlin
// src/test/kotlin/com/aibles/iam/authorization/infra/authserver/OidcTokenCustomizerTest.kt
package com.aibles.iam.authorization.infra.authserver

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.core.OAuth2TokenType as TokenType
import java.time.Instant
import java.util.UUID

class OidcTokenCustomizerTest {

    private val userRepository = mockk<UserRepository>()
    private val customizer = OidcTokenCustomizer(userRepository)

    private val googleSub = "google-sub-123"
    private val testUser = User.create("user@example.com", "Test User")

    private fun buildContext(tokenTypeName: String, principalName: String): JwtEncodingContext {
        val authentication = mockk<Authentication>()
        every { authentication.name } returns principalName

        val claims = JwtClaimsSet.builder().subject(principalName).build()
        val header = JwsHeader.with { "RS256" }.build()

        return mockk<JwtEncodingContext> {
            every { tokenType } returns TokenType(tokenTypeName)
            every { getPrincipal<Authentication>() } returns authentication
            every { this@mockk.claims } returns JwtClaimsSet.from(claims)
        }
    }

    @Test
    fun `customize enriches ID token with email, name, and roles`() {
        every { userRepository.findByGoogleSub(googleSub) } returns testUser

        val ctx = buildContext(OidcParameterNames.ID_TOKEN, googleSub)
        customizer.customize(ctx)

        verify { ctx.claims.claim("email", testUser.email) }
        verify { ctx.claims.claim("name", testUser.displayName ?: testUser.email) }
        verify { ctx.claims.claim("roles", testUser.roles.toList()) }
    }

    @Test
    fun `customize does nothing for access tokens`() {
        val ctx = buildContext(OAuth2TokenType.ACCESS_TOKEN.value, googleSub)
        customizer.customize(ctx)

        verify(exactly = 0) { userRepository.findByGoogleSub(any()) }
    }

    @Test
    fun `customize does nothing when user not found`() {
        every { userRepository.findByGoogleSub(googleSub) } returns null

        val ctx = buildContext(OidcParameterNames.ID_TOKEN, googleSub)
        customizer.customize(ctx)  // must not throw
    }
}
```

### Step 2: Run the test to verify it fails

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.authserver.OidcTokenCustomizerTest" 2>&1 | tail -20
```

Expected: FAIL — `OidcTokenCustomizer` class does not exist yet.

---

### Step 3: Implement `OidcTokenCustomizer`

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/infra/authserver/OidcTokenCustomizer.kt
package com.aibles.iam.authorization.infra.authserver

import com.aibles.iam.identity.domain.user.UserRepository
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.stereotype.Component

@Component
class OidcTokenCustomizer(
    private val userRepository: UserRepository,
) : OAuth2TokenCustomizer<JwtEncodingContext> {

    override fun customize(context: JwtEncodingContext) {
        if (OidcParameterNames.ID_TOKEN != context.tokenType.value) return

        val googleSub = context.getPrincipal<Authentication>().name
        val user = userRepository.findByGoogleSub(googleSub) ?: return

        context.claims
            .claim("email", user.email)
            .claim("name", user.displayName ?: user.email)
            .claim("roles", user.roles.toList())
    }
}
```

---

### Step 4: Run the test to verify it passes

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.authserver.OidcTokenCustomizerTest" 2>&1 | tail -20
```

Expected: PASS

### Step 5: Run full test suite

```bash
./gradlew test 2>&1 | tail -10
```

Expected: `BUILD SUCCESSFUL`

### Step 6: Commit

```bash
git add \
  src/main/kotlin/com/aibles/iam/authorization/infra/authserver/OidcTokenCustomizer.kt \
  src/test/kotlin/com/aibles/iam/authorization/infra/authserver/OidcTokenCustomizerTest.kt
git commit -m "feat(authorization): OIDC token customizer enriches ID token with user claims (Closes #<issue-19-number>)"
```

Then push, create PR, squash merge, delete branch, pull main.

---

## Task 3: OAuth2 Client Seeder (Issue #20)

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authorization/infra/authserver/OAuth2ClientSeeder.kt`
- Modify: `src/main/resources/application.yml` (add `oauth2.clients` config block)
- Create: `src/test/kotlin/com/aibles/iam/authorization/infra/authserver/OAuth2ClientSeederTest.kt`

**Context:** Seeds two clients on startup if they do not already exist:
1. `iam-web` — public client (Authorization Code + PKCE, no client secret, `openid email profile` scopes)
2. `iam-service` — confidential client (Client Credentials, `iam:read iam:write` scopes)

The seeder is idempotent: checks `findByClientId` first, saves only if absent. Client properties (redirect URI, client secret) come from configuration so they can be overridden via environment variables.

---

### Step 1: Write the failing unit test

```kotlin
// src/test/kotlin/com/aibles/iam/authorization/infra/authserver/OAuth2ClientSeederTest.kt
package com.aibles.iam.authorization.infra.authserver

import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository

class OAuth2ClientSeederTest {

    private val repository = mockk<RegisteredClientRepository>(relaxed = true)
    private val properties = OAuth2ClientSeeder.Properties(
        iamWeb = OAuth2ClientSeeder.Properties.IamWebProperties(
            redirectUri = "http://localhost:3000/callback"
        ),
        iamService = OAuth2ClientSeeder.Properties.IamServiceProperties(
            clientSecret = "{noop}test-secret"
        ),
    )
    private val seeder = OAuth2ClientSeeder(repository, properties)

    @Test
    fun `seeds iam-web client when not present`() {
        every { repository.findByClientId("iam-web") } returns null
        every { repository.findByClientId("iam-service") } returns null

        seeder.run(mockk())

        val slot = slot<RegisteredClient>()
        verify { repository.save(capture(slot)) }

        val saved = slot.captured
        assertThat(saved.clientId).isEqualTo("iam-web")
        assertThat(saved.clientSettings.isRequireProofKey).isTrue()
        assertThat(saved.scopes).contains("openid")
    }

    @Test
    fun `skips iam-web client when already present`() {
        every { repository.findByClientId("iam-web") } returns mockk()
        every { repository.findByClientId("iam-service") } returns null

        seeder.run(mockk())

        verify(exactly = 0) { repository.save(match { it.clientId == "iam-web" }) }
        verify(exactly = 1) { repository.save(match { it.clientId == "iam-service" }) }
    }

    @Test
    fun `seeds iam-service with CLIENT_CREDENTIALS grant`() {
        every { repository.findByClientId(any()) } returns null

        seeder.run(mockk())

        verify {
            repository.save(match { client ->
                client.clientId == "iam-service" &&
                    client.authorizationGrantTypes.any { it.value == "client_credentials" }
            })
        }
    }
}
```

### Step 2: Run the test to verify it fails

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.authserver.OAuth2ClientSeederTest" 2>&1 | tail -20
```

Expected: FAIL — `OAuth2ClientSeeder` does not exist yet.

---

### Step 3: Add client properties to `application.yml`

```yaml
# append to application.yml
oauth2:
  clients:
    iam-web:
      redirect-uri: ${IAM_WEB_REDIRECT_URI:http://localhost:3000/callback}
    iam-service:
      client-secret: ${IAM_SERVICE_CLIENT_SECRET:"{noop}changeme"}
```

---

### Step 4: Implement `OAuth2ClientSeeder`

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/infra/authserver/OAuth2ClientSeeder.kt
package com.aibles.iam.authorization.infra.authserver

import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Component
import java.util.UUID

@Component
@EnableConfigurationProperties(OAuth2ClientSeeder.Properties::class)
class OAuth2ClientSeeder(
    private val registeredClientRepository: RegisteredClientRepository,
    private val properties: Properties,
) : ApplicationRunner {

    @ConfigurationProperties("oauth2.clients")
    data class Properties(
        val iamWeb: IamWebProperties = IamWebProperties(),
        val iamService: IamServiceProperties = IamServiceProperties(),
    ) {
        data class IamWebProperties(val redirectUri: String = "http://localhost:3000/callback")
        data class IamServiceProperties(val clientSecret: String = "{noop}changeme")
    }

    override fun run(args: ApplicationArguments) {
        seedIfAbsent(buildIamWebClient())
        seedIfAbsent(buildIamServiceClient())
    }

    private fun seedIfAbsent(client: RegisteredClient) {
        if (registeredClientRepository.findByClientId(client.clientId) == null) {
            registeredClientRepository.save(client)
        }
    }

    private fun buildIamWebClient() = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("iam-web")
        .clientName("IAM Web Application")
        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(properties.iamWeb.redirectUri)
        .scope(OidcScopes.OPENID)
        .scope(OidcScopes.EMAIL)
        .scope(OidcScopes.PROFILE)
        .clientSettings(ClientSettings.builder().requireProofKey(true).build())
        .tokenSettings(TokenSettings.builder().build())
        .build()

    private fun buildIamServiceClient() = RegisteredClient
        .withId(UUID.randomUUID().toString())
        .clientId("iam-service")
        .clientName("IAM Service (machine-to-machine)")
        .clientSecret(properties.iamService.clientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .scope("iam:read")
        .scope("iam:write")
        .clientSettings(ClientSettings.builder().build())
        .tokenSettings(TokenSettings.builder().build())
        .build()
}
```

---

### Step 5: Run the test to verify it passes

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.authserver.OAuth2ClientSeederTest" 2>&1 | tail -20
```

Expected: PASS

### Step 6: Run the full test suite

```bash
./gradlew test 2>&1 | tail -10
```

Expected: `BUILD SUCCESSFUL`

### Step 7: Commit

```bash
git add \
  src/main/kotlin/com/aibles/iam/authorization/infra/authserver/OAuth2ClientSeeder.kt \
  src/main/resources/application.yml
git add src/test/kotlin/com/aibles/iam/authorization/infra/authserver/OAuth2ClientSeederTest.kt
git commit -m "feat(authorization): OAuth2 client seeder seeds iam-web and iam-service on startup (Closes #<issue-20-number>)"
```

Then push, create PR, squash merge, delete branch, pull main.

---

## Final Verification

After all three tasks are merged, pull `main` and run the full test suite one more time:

```bash
git checkout main && git pull origin main
./gradlew test 2>&1 | tail -10
```

Expected: `BUILD SUCCESSFUL` with all tests passing (including `AuthorizationServerConfigTest`, `OidcTokenCustomizerTest`, `OAuth2ClientSeederTest`).

### Manual smoke-test (optional, requires Docker Compose running)

```bash
docker compose up -d
# Generate RSA key pair and export JWT_PRIVATE_KEY / JWT_PUBLIC_KEY
./gradlew bootRun

# Verify OIDC discovery
curl -s http://localhost:8080/.well-known/openid-configuration | jq .

# Verify JWK Set
curl -s http://localhost:8080/oauth2/jwks | jq .

# Client credentials flow (iam-service)
curl -s -X POST http://localhost:8080/oauth2/token \
  -u "iam-service:changeme" \
  -d "grant_type=client_credentials&scope=iam:read" | jq .
```

Expected: OIDC discovery returns JSON with `issuer`, `jwks_uri`, `token_endpoint`. Client credentials flow returns `access_token`.
