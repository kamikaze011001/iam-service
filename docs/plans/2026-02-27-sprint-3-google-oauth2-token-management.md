# Sprint 3: Google OAuth2 + Token Management

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Implement JWT-based authentication — RS256 access tokens, rotating Redis refresh tokens, Google OAuth2 login that issues tokens, and logout/refresh endpoints.

**Architecture:** Five isolated GitHub issues executed sequentially per CLAUDE.md workflow (branch → TDD → PR → merge → next). The `authorization` BC owns JWT and token store infrastructure. The `authentication` BC owns login flows. Spring Security is reconfigured from "permit all" to JWT bearer auth protecting all `/api/v1/**` endpoints.

**Tech Stack:** Spring Security 6 OAuth2 Client, `spring-security-oauth2-jose` (Nimbus JOSE+JWT — already transitive), Spring Data Redis (Lettuce), Testcontainers Redis (GenericContainer), MockK for use case tests, `@WebMvcTest` + `@MockkBean` for controller tests.

---

## Pre-work: Create GitHub Issues

Before touching code, create all five GitHub issues for this sprint:

```bash
gh issue create --title "feat: JWT service + RSA key loading" \
  --body "RS256 JWT generation and validation using Nimbus JOSE+JWT. JwtProperties config binding. JwtServiceTest with inline RSA key pair." \
  --label "sprint-3,authorization"

gh issue create --title "feat: Redis refresh token store" \
  --body "TokenStore interface + RedisTokenStore implementation. Keys: rt:{token}→userId, rt:u:{userId}→Set<token>. Testcontainers Redis tests." \
  --label "sprint-3,authorization"

gh issue create --title "feat: IssueTokenUseCase + RefreshTokenUseCase + RevokeTokenUseCase" \
  --body "Three token management use cases. IssueTokenUseCase generates access+refresh pair. RefreshTokenUseCase rotates refresh. RevokeTokenUseCase invalidates." \
  --label "sprint-3,authorization"

gh issue create --title "feat: Google OAuth2 post-login handler + SecurityConfig" \
  --body "LoginWithGoogleUseCase (find-or-create user, recordLogin, issue tokens). GoogleOAuth2SuccessHandler writes ApiResponse JSON. SecurityConfig enforces JWT bearer auth on /api/v1/**." \
  --label "sprint-3,authentication"

gh issue create --title "feat: Auth REST controller (refresh + logout)" \
  --body "AuthController: POST /api/v1/auth/refresh and POST /api/v1/auth/logout. AuthControllerTest with MockkBean use cases." \
  --label "sprint-3,authentication,api"
```

Note the issue numbers from the output (e.g., `#15`, `#16`...) — use them in branch names and PR bodies.

---

## Task 1: JWT Service + RSA Key Loading

**GitHub Issue:** first issue created above (e.g., `#15`)

**Branch:** `feature/<issue-number>-jwt-service`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/config/JwtProperties.kt`
- Create: `src/main/kotlin/com/aibles/iam/authorization/infra/JwtService.kt`
- Modify: `src/main/kotlin/com/aibles/iam/IamApplication.kt` — add `@EnableConfigurationProperties`
- Modify: `src/main/resources/application.yml` — add `jwt:` section
- Create: `src/test/kotlin/com/aibles/iam/authorization/infra/JwtServiceTest.kt`

### Step 1.1: Create failing test

```kotlin
// src/test/kotlin/com/aibles/iam/authorization/infra/JwtServiceTest.kt
package com.aibles.iam.authorization.infra

import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.error.UnauthorizedException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.UUID

class JwtServiceTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }.generateKeyPair()

    private val props = JwtProperties(
        privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded),
        publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded),
        accessTokenTtlMinutes = 15,
    )
    private val service = JwtService(props)

    @Test
    fun `generated token contains correct claims`() {
        val userId = UUID.randomUUID()
        val token = service.generateAccessToken(userId, "a@b.com", setOf("USER"))
        val decoded = service.validate(token)
        assertThat(decoded.subject).isEqualTo(userId.toString())
        assertThat(decoded.getClaimAsString("email")).isEqualTo("a@b.com")
    }

    @Test
    fun `tampered token is rejected with UnauthorizedException`() {
        val token = service.generateAccessToken(UUID.randomUUID(), "a@b.com", setOf("USER"))
        val tampered = token.dropLast(5) + "XXXXX"
        assertThrows<UnauthorizedException> { service.validate(tampered) }
    }

    @Test
    fun `expired token is rejected with UnauthorizedException`() {
        val expiredProps = props.copy(accessTokenTtlMinutes = -1)  // exp is in the past
        val expiredService = JwtService(expiredProps)
        val token = expiredService.generateAccessToken(UUID.randomUUID(), "a@b.com", setOf("USER"))
        assertThrows<UnauthorizedException> { expiredService.validate(token) }
    }
}
```

### Step 1.2: Verify RED

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.JwtServiceTest"
# Expected: FAILED — "Unresolved reference: JwtService"
```

### Step 1.3: Create `JwtProperties.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/JwtProperties.kt
package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("jwt")
data class JwtProperties(
    val privateKey: String = "",   // Base64-encoded PKCS#8 DER
    val publicKey: String = "",    // Base64-encoded X.509 DER
    val accessTokenTtlMinutes: Long = 15,
)
```

### Step 1.4: Enable config properties in IamApplication

Add `@EnableConfigurationProperties(JwtProperties::class)` to the class:

```kotlin
// src/main/kotlin/com/aibles/iam/IamApplication.kt
package com.aibles.iam

import com.aibles.iam.shared.config.JwtProperties
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(JwtProperties::class)
class IamApplication

fun main(args: Array<String>) {
    runApplication<IamApplication>(*args)
}
```

### Step 1.5: Create `JwtService.kt`

Uses `spring-security-oauth2-jose` (Nimbus JOSE+JWT) which is already a transitive dependency via `spring-security-oauth2-authorization-server`.

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/infra/JwtService.kt
package com.aibles.iam.authorization.infra

import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtException
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Base64
import java.util.UUID

@Component
class JwtService(private val props: JwtProperties) {

    private val encoder: NimbusJwtEncoder
    private val decoder: NimbusJwtDecoder

    init {
        val kf = KeyFactory.getInstance("RSA")
        val privateKey = kf.generatePrivate(
            PKCS8EncodedKeySpec(Base64.getDecoder().decode(props.privateKey))
        ) as RSAPrivateKey
        val publicKey = kf.generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(props.publicKey))
        ) as RSAPublicKey

        val rsaKey = RSAKey.Builder(publicKey).privateKey(privateKey).build()
        encoder = NimbusJwtEncoder(ImmutableJWKSet(JWKSet(rsaKey)))
        decoder = NimbusJwtDecoder.withPublicKey(publicKey).build()
    }

    fun generateAccessToken(userId: UUID, email: String, roles: Set<String>): String {
        val now = Instant.now()
        val expiry = now.plus(props.accessTokenTtlMinutes, ChronoUnit.MINUTES)
        val claims = JwtClaimsSet.builder()
            .subject(userId.toString())
            .claim("email", email)
            .claim("roles", roles.toList())
            .issuedAt(now)
            .expiresAt(expiry)
            .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).build()
        return encoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }

    fun validate(token: String): Jwt {
        try {
            return decoder.decode(token)
        } catch (e: JwtException) {
            throw UnauthorizedException(e.message ?: "Invalid token", ErrorCode.TOKEN_INVALID)
        }
    }
}
```

### Step 1.6: Add JWT config to `application.yml`

```yaml
jwt:
  private-key: ${JWT_PRIVATE_KEY:}
  public-key: ${JWT_PUBLIC_KEY:}
  access-token-ttl-minutes: ${JWT_TTL_MINUTES:15}
```

Add these lines to the existing `application.yml` (top-level, after `server:` block).

### Step 1.7: Verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.JwtServiceTest"
# Expected: BUILD SUCCESSFUL — 3 tests passed
```

### Step 1.8: Commit and merge

```bash
git add src/
git commit -m "feat(authorization): JWT service with RS256 sign/validate (Closes #<N>)"
git push -u origin feature/<N>-jwt-service
gh pr create --title "feat(authorization): JWT service + RSA key loading" \
  --base main --body "Closes #<N>"
gh pr merge <PR-number> --squash --delete-branch
git checkout main && git pull
```

---

## Task 2: Redis Refresh Token Store

**GitHub Issue:** second issue created above (e.g., `#16`)

**Branch:** `feature/<issue-number>-redis-token-store`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authorization/domain/token/TokenStore.kt`
- Create: `src/main/kotlin/com/aibles/iam/authorization/infra/RedisTokenStore.kt`
- Create: `src/test/kotlin/com/aibles/iam/authorization/infra/RedisTokenStoreTest.kt`

**Dependencies to add in `build.gradle.kts`:**
```kotlin
testImplementation("org.testcontainers:redis")
```

### Step 2.1: Create failing test

```kotlin
// src/test/kotlin/com/aibles/iam/authorization/infra/RedisTokenStoreTest.kt
package com.aibles.iam.authorization.infra

import com.aibles.iam.shared.error.UnauthorizedException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.containers.GenericContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.time.Duration
import java.util.UUID

@Testcontainers
class RedisTokenStoreTest {

    companion object {
        @Container
        val redis = GenericContainer<Nothing>("redis:7-alpine").apply {
            withExposedPorts(6379)
        }
    }

    private fun buildTemplate(): StringRedisTemplate {
        val factory = LettuceConnectionFactory("localhost", redis.getMappedPort(6379))
        factory.afterPropertiesSet()
        return StringRedisTemplate(factory).apply { afterPropertiesSet() }
    }

    private val template = buildTemplate()
    private val store = RedisTokenStore(template)

    @AfterEach
    fun flush() {
        template.connectionFactory?.connection?.serverCommands()?.flushAll()
    }

    @Test
    fun `store and consume returns correct userId`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.storeRefreshToken(token, userId, Duration.ofMinutes(30))

        val returned = store.validateAndConsume(token)
        assertThat(returned).isEqualTo(userId)
    }

    @Test
    fun `consuming same token twice throws UnauthorizedException`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.storeRefreshToken(token, userId, Duration.ofMinutes(30))

        store.validateAndConsume(token)  // first consume succeeds

        assertThrows<UnauthorizedException> {
            store.validateAndConsume(token)  // second must fail
        }
    }

    @Test
    fun `expired token throws UnauthorizedException`() {
        val userId = UUID.randomUUID()
        val token = UUID.randomUUID().toString()
        store.storeRefreshToken(token, userId, Duration.ofMillis(100))

        Thread.sleep(300)  // wait for expiry

        assertThrows<UnauthorizedException> {
            store.validateAndConsume(token)
        }
    }

    @Test
    fun `revokeAllForUser removes all tokens for that user`() {
        val userId = UUID.randomUUID()
        val t1 = UUID.randomUUID().toString()
        val t2 = UUID.randomUUID().toString()
        store.storeRefreshToken(t1, userId, Duration.ofMinutes(30))
        store.storeRefreshToken(t2, userId, Duration.ofMinutes(30))

        store.revokeAllForUser(userId)

        assertThrows<UnauthorizedException> { store.validateAndConsume(t1) }
        assertThrows<UnauthorizedException> { store.validateAndConsume(t2) }
    }
}
```

### Step 2.2: Verify RED

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.RedisTokenStoreTest"
# Expected: FAILED — compilation error (TokenStore/RedisTokenStore not found)
```

### Step 2.3: Create `TokenStore.kt` interface

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/domain/token/TokenStore.kt
package com.aibles.iam.authorization.domain.token

import java.time.Duration
import java.util.UUID

interface TokenStore {
    fun storeRefreshToken(token: String, userId: UUID, ttl: Duration)
    fun validateAndConsume(token: String): UUID  // atomic get+delete; throws TOKEN_INVALID if missing/expired
    fun revokeAllForUser(userId: UUID)
}
```

### Step 2.4: Create `RedisTokenStore.kt`

Key scheme:
- `rt:{token}` → `userId` string, with TTL
- `rt:u:{userId}` → Redis Set of token strings (secondary index for revoke-all)

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/infra/RedisTokenStore.kt
package com.aibles.iam.authorization.infra

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.UUID

@Component
class RedisTokenStore(private val template: StringRedisTemplate) : TokenStore {

    override fun storeRefreshToken(token: String, userId: UUID, ttl: Duration) {
        template.opsForValue().set("rt:$token", userId.toString(), ttl)
        template.opsForSet().add("rt:u:$userId", token)
    }

    override fun validateAndConsume(token: String): UUID {
        val userId = template.opsForValue().getAndDelete("rt:$token")
            ?: throw UnauthorizedException("Refresh token invalid or expired", ErrorCode.TOKEN_INVALID)
        return UUID.fromString(userId)
    }

    override fun revokeAllForUser(userId: UUID) {
        val tokens = template.opsForSet().members("rt:u:$userId") ?: emptySet()
        tokens.forEach { token -> template.delete("rt:$token") }
        template.delete("rt:u:$userId")
    }
}
```

### Step 2.5: Verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.RedisTokenStoreTest"
# Expected: BUILD SUCCESSFUL — 4 tests passed (Testcontainers spins up Redis)
```

### Step 2.6: Run full suite

```bash
./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass
```

### Step 2.7: Commit and merge

```bash
git add src/ build.gradle.kts
git commit -m "feat(authorization): Redis refresh token store with atomic consume (Closes #<N>)"
git push -u origin feature/<N>-redis-token-store
gh pr create --title "feat(authorization): Redis refresh token store" \
  --base main --body "Closes #<N>"
gh pr merge <PR-number> --squash --delete-branch
git checkout main && git pull
```

---

## Task 3: Token Use Cases

**GitHub Issue:** third issue created above (e.g., `#17`)

**Branch:** `feature/<issue-number>-token-use-cases`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authorization/usecase/IssueTokenUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authorization/usecase/RefreshTokenUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/authorization/usecase/IssueTokenUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authorization/usecase/RefreshTokenUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCaseTest.kt`

### Step 3.1: Create failing tests

**`IssueTokenUseCaseTest.kt`:**
```kotlin
package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.authorization.infra.JwtService
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.config.JwtProperties
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.util.Base64

class IssueTokenUseCaseTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }.generateKeyPair()
    private val props = JwtProperties(
        privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded),
        publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded),
        accessTokenTtlMinutes = 15,
    )
    private val jwtService = JwtService(props)
    private val tokenStore = mockk<TokenStore>()
    private val useCase = IssueTokenUseCase(jwtService, tokenStore, props)

    @Test
    fun `issues access and refresh tokens for active user`() {
        val user = User.create("a@b.com")
        justRun { tokenStore.storeRefreshToken(any(), user.id, any()) }

        val result = useCase.execute(IssueTokenUseCase.Command(user))

        assertThat(result.accessToken).isNotBlank()
        assertThat(result.refreshToken).isNotBlank()
        assertThat(result.expiresIn).isEqualTo(15 * 60)
        verify(exactly = 1) { tokenStore.storeRefreshToken(result.refreshToken, user.id, any()) }
    }

    @Test
    fun `access token contains correct sub and email claims`() {
        val user = User.create("b@example.com")
        justRun { tokenStore.storeRefreshToken(any(), any(), any()) }

        val result = useCase.execute(IssueTokenUseCase.Command(user))
        val decoded = jwtService.validate(result.accessToken)

        assertThat(decoded.subject).isEqualTo(user.id.toString())
        assertThat(decoded.getClaimAsString("email")).isEqualTo("b@example.com")
    }
}
```

**`RefreshTokenUseCaseTest.kt`:**
```kotlin
package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.authorization.infra.JwtService
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.config.JwtProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import com.aibles.iam.shared.error.UnauthorizedException
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.KeyPairGenerator
import java.util.Base64
import java.util.UUID

class RefreshTokenUseCaseTest {

    private val keyPair = KeyPairGenerator.getInstance("RSA")
        .apply { initialize(2048) }.generateKeyPair()
    private val props = JwtProperties(
        privateKey = Base64.getEncoder().encodeToString(keyPair.private.encoded),
        publicKey = Base64.getEncoder().encodeToString(keyPair.public.encoded),
        accessTokenTtlMinutes = 15,
    )
    private val tokenStore = mockk<TokenStore>()
    private val getUserUseCase = mockk<GetUserUseCase>()
    private val jwtService = JwtService(props)
    private val issueToken = IssueTokenUseCase(jwtService, tokenStore, props)
    private val useCase = RefreshTokenUseCase(tokenStore, getUserUseCase, issueToken)

    @Test
    fun `valid refresh token returns new token pair`() {
        val user = User.create("a@b.com")
        every { tokenStore.validateAndConsume("rt-abc") } returns user.id
        every { getUserUseCase.execute(GetUserUseCase.Query(user.id)) } returns user
        justRun { tokenStore.storeRefreshToken(any(), user.id, any()) }

        val result = useCase.execute(RefreshTokenUseCase.Command("rt-abc"))
        assertThat(result.accessToken).isNotBlank()
        assertThat(result.refreshToken).isNotBlank()
    }

    @Test
    fun `disabled user throws ForbiddenException with USER_DISABLED`() {
        val user = User.create("a@b.com").also { it.disable() }
        every { tokenStore.validateAndConsume("rt-xyz") } returns user.id
        every { getUserUseCase.execute(GetUserUseCase.Query(user.id)) } returns user

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(RefreshTokenUseCase.Command("rt-xyz"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
    }

    @Test
    fun `invalid refresh token throws UnauthorizedException with TOKEN_INVALID`() {
        every { tokenStore.validateAndConsume("bad-token") } throws
            UnauthorizedException("expired", ErrorCode.TOKEN_INVALID)

        val ex = assertThrows<UnauthorizedException> {
            useCase.execute(RefreshTokenUseCase.Command("bad-token"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.TOKEN_INVALID)
    }
}
```

**`RevokeTokenUseCaseTest.kt`:**
```kotlin
package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import org.junit.jupiter.api.Test

class RevokeTokenUseCaseTest {

    private val tokenStore = mockk<TokenStore>()
    private val useCase = RevokeTokenUseCase(tokenStore)

    @Test
    fun `valid token is consumed from store`() {
        justRun { tokenStore.validateAndConsume("good-token") }

        useCase.execute(RevokeTokenUseCase.Command("good-token"))

        verify(exactly = 1) { tokenStore.validateAndConsume("good-token") }
    }

    @Test
    fun `already-revoked token does not throw (idempotent logout)`() {
        every { tokenStore.validateAndConsume("gone-token") } throws
            UnauthorizedException("expired", ErrorCode.TOKEN_INVALID)

        // should NOT throw — logout is idempotent
        useCase.execute(RevokeTokenUseCase.Command("gone-token"))
    }
}
```

### Step 3.2: Verify RED

```bash
./gradlew test --tests "com.aibles.iam.authorization.usecase.*"
# Expected: FAILED — compilation errors (use cases don't exist yet)
```

### Step 3.3: Implement `IssueTokenUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/usecase/IssueTokenUseCase.kt
package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.authorization.infra.JwtService
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.config.JwtProperties
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.UUID

@Component
class IssueTokenUseCase(
    private val jwtService: JwtService,
    private val tokenStore: TokenStore,
    private val props: JwtProperties,
) {
    data class Command(val user: User)
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val accessToken = jwtService.generateAccessToken(
            command.user.id, command.user.email, command.user.roles
        )
        val refreshToken = UUID.randomUUID().toString()
        tokenStore.storeRefreshToken(refreshToken, command.user.id, Duration.ofDays(30))
        return Result(accessToken, refreshToken, props.accessTokenTtlMinutes * 60)
    }
}
```

### Step 3.4: Implement `RefreshTokenUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/usecase/RefreshTokenUseCase.kt
package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import org.springframework.stereotype.Component

@Component
class RefreshTokenUseCase(
    private val tokenStore: TokenStore,
    private val getUserUseCase: GetUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
) {
    data class Command(val refreshToken: String)

    fun execute(command: Command): IssueTokenUseCase.Result {
        val userId = tokenStore.validateAndConsume(command.refreshToken)
        val user = getUserUseCase.execute(GetUserUseCase.Query(userId))
        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)
        return issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
    }
}
```

### Step 3.5: Implement `RevokeTokenUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt
package com.aibles.iam.authorization.usecase

import com.aibles.iam.authorization.domain.token.TokenStore
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.stereotype.Component

@Component
class RevokeTokenUseCase(private val tokenStore: TokenStore) {
    data class Command(val refreshToken: String)

    fun execute(command: Command) {
        try {
            tokenStore.validateAndConsume(command.refreshToken)
        } catch (e: UnauthorizedException) {
            // already revoked/expired — logout is idempotent
        }
    }
}
```

### Step 3.6: Verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authorization.usecase.*"
# Expected: BUILD SUCCESSFUL — all tests passed
./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass (full suite)
```

### Step 3.7: Commit and merge

```bash
git add src/
git commit -m "feat(authorization): IssueToken, RefreshToken, RevokeToken use cases (Closes #<N>)"
git push -u origin feature/<N>-token-use-cases
gh pr create --title "feat(authorization): token management use cases" \
  --base main --body "Closes #<N>"
gh pr merge <PR-number> --squash --delete-branch
git checkout main && git pull
```

---

## Task 4: Google OAuth2 + SecurityConfig

**GitHub Issue:** fourth issue created above (e.g., `#18`)

**Branch:** `feature/<issue-number>-google-oauth2`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/TokenResponse.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCaseTest.kt`

### Step 4.1: Create failing test

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCaseTest.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import java.time.Instant
import java.util.Optional

class LoginWithGoogleUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val useCase = LoginWithGoogleUseCase(userRepository, createUserUseCase, issueTokenUseCase)

    private fun oidcUser(sub: String, email: String, name: String? = "Test User"): DefaultOidcUser {
        val idToken = OidcIdToken(
            "id-token-value",
            Instant.now(),
            Instant.now().plusSeconds(3600),
            mapOf("sub" to sub, "iss" to "https://accounts.google.com")
        )
        val userInfo = OidcUserInfo(
            mapOf("sub" to sub, "email" to email, "name" to name)
        )
        val authority = OidcUserAuthority(idToken, userInfo)
        return DefaultOidcUser(listOf(authority), idToken, userInfo, "sub")
    }

    @Test
    fun `new user is created on first Google login`() {
        val oidcUser = oidcUser("google-sub-123", "new@example.com")
        val newUser = User.create("new@example.com", "Test User")
        every { userRepository.findByGoogleSub("google-sub-123") } returns null
        every { userRepository.findByEmail("new@example.com") } returns null
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(newUser)
        every { userRepository.save(newUser) } returns newUser
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))

        assertThat(result.accessToken).isEqualTo("access")
        verify(exactly = 1) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `existing user by googleSub is returned on second login`() {
        val existingUser = User.create("existing@example.com", "Alice", "google-sub-456")
        val oidcUser = oidcUser("google-sub-456", "existing@example.com", "Alice")
        every { userRepository.findByGoogleSub("google-sub-456") } returns existingUser
        every { userRepository.save(existingUser) } returns existingUser
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access2", "refresh2", 900)

        val result = useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))

        assertThat(result.accessToken).isEqualTo("access2")
        verify(exactly = 0) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `disabled user throws ForbiddenException with USER_DISABLED`() {
        val disabledUser = User.create("disabled@example.com").also { it.disable() }
        val oidcUser = oidcUser("google-sub-789", "disabled@example.com")
        every { userRepository.findByGoogleSub("google-sub-789") } returns disabledUser
        every { userRepository.save(disabledUser) } returns disabledUser

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
    }
}
```

### Step 4.2: Verify RED

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.LoginWithGoogleUseCaseTest"
# Expected: FAILED — "Unresolved reference: LoginWithGoogleUseCase"
```

### Step 4.3: Create `TokenResponse.kt` DTO

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/TokenResponse.kt
package com.aibles.iam.authentication.api.dto

data class TokenResponse(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Long,
)
```

### Step 4.4: Create `LoginWithGoogleUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCase.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component

@Component
class LoginWithGoogleUseCase(
    private val userRepository: UserRepository,
    private val createUserUseCase: CreateUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
) {
    data class Command(val oidcUser: OidcUser)
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val oidcUser = command.oidcUser
        val googleSub = oidcUser.subject
        val email = oidcUser.email ?: error("Google OIDC user missing email")
        val name = oidcUser.fullName

        val user = userRepository.findByGoogleSub(googleSub)
            ?: userRepository.findByEmail(email)
            ?: createUserUseCase.execute(CreateUserUseCase.Command(email, name, googleSub)).user

        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        user.recordLogin()
        userRepository.save(user)

        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
```

### Step 4.5: Create `GoogleOAuth2SuccessHandler.kt`

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
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2SuccessHandler(
    private val loginWithGoogleUseCase: LoginWithGoogleUseCase,
    private val objectMapper: ObjectMapper,
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val oidcUser = authentication.principal as OidcUser
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(oidcUser))
        val tokenResponse = TokenResponse(result.accessToken, result.refreshToken, result.expiresIn)

        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpServletResponse.SC_OK
        objectMapper.writeValue(response.writer, ApiResponse.ok(tokenResponse))
    }
}
```

### Step 4.6: Update `SecurityConfig.kt`

Replace the existing placeholder with JWT bearer auth + OAuth2 login:

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt
package com.aibles.iam.shared.config

import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Configuration
@EnableWebSecurity
class SecurityConfig(
    private val jwtProperties: JwtProperties,
    private val googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler,
) {

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers(
                        "/oauth2/**", "/login/**",
                        "/api/v1/auth/**",
                        "/actuator/**",
                        "/swagger-ui/**", "/v3/api-docs/**",
                    ).permitAll()
                    .anyRequest().authenticated()
            }
            .oauth2Login { it.successHandler(googleOAuth2SuccessHandler) }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(jwtDecoder()) } }
        return http.build()
    }

    @Bean
    fun jwtDecoder(): NimbusJwtDecoder {
        // Only configure if public key is set (skip in tests where it may be empty)
        if (jwtProperties.publicKey.isBlank()) {
            return NimbusJwtDecoder.withPublicKey(generateTestKey()).build()
        }
        val publicKey = KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(jwtProperties.publicKey))) as RSAPublicKey
        return NimbusJwtDecoder.withPublicKey(publicKey).build()
    }

    private fun generateTestKey(): RSAPublicKey {
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        return kpg.generateKeyPair().public as RSAPublicKey
    }
}
```

> **Note:** The `generateTestKey()` fallback is needed only when `JWT_PUBLIC_KEY` is not set (e.g., in `@WebMvcTest` slices). For `@WebMvcTest` tests, Spring Security filters are disabled with `addFilters = false`, so this path is never hit at runtime.

### Step 4.7: Verify tests pass

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.LoginWithGoogleUseCaseTest"
# Expected: 3 tests pass
./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass
```

> **Troubleshooting:** If `@WebMvcTest` tests fail because Spring tries to instantiate `SecurityConfig`, add `@MockkBean` for `GoogleOAuth2SuccessHandler` and `JwtProperties` in any affected test classes, or add `@AutoConfigureMockMvc(addFilters = false)` which was already there.

### Step 4.8: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): Google OAuth2 login with token issuance + SecurityConfig JWT auth (Closes #<N>)"
git push -u origin feature/<N>-google-oauth2
gh pr create --title "feat(authentication): Google OAuth2 + SecurityConfig JWT bearer" \
  --base main --body "Closes #<N>"
gh pr merge <PR-number> --squash --delete-branch
git checkout main && git pull
```

---

## Task 5: Auth REST Controller (Refresh + Logout)

**GitHub Issue:** fifth issue created above (e.g., `#19`)

**Branch:** `feature/<issue-number>-auth-controller`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/AuthController.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/RefreshTokenRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/LogoutRequest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/api/AuthControllerTest.kt`

### Step 5.1: Create failing test (RED)

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/api/AuthControllerTest.kt
package com.aibles.iam.authentication.api

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.identity.usecase.ChangeUserStatusUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.identity.usecase.DeleteUserUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.identity.usecase.UpdateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.GlobalExceptionHandler
import com.aibles.iam.shared.error.UnauthorizedException
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import io.mockk.justRun
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

@WebMvcTest
@Import(GlobalExceptionHandler::class, AuthController::class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired lateinit var mockMvc: MockMvc
    // AuthController deps
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase
    // UsersController deps (scanned by @WebMvcTest)
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase

    @Test
    fun `POST refresh returns 200 with new token pair`() {
        every { refreshTokenUseCase.execute(any()) } returns
            IssueTokenUseCase.Result("new-access", "new-refresh", 900)

        mockMvc.post("/api/v1/auth/refresh") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"refreshToken":"old-token"}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.accessToken") { value("new-access") }
            jsonPath("$.data.refreshToken") { value("new-refresh") }
            jsonPath("$.data.expiresIn") { value(900) }
        }
    }

    @Test
    fun `POST refresh with invalid token returns 401`() {
        every { refreshTokenUseCase.execute(any()) } throws
            UnauthorizedException("Token invalid", ErrorCode.TOKEN_INVALID)

        mockMvc.post("/api/v1/auth/refresh") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"refreshToken":"bad-token"}"""
        }.andExpect {
            status { isUnauthorized() }
            jsonPath("$.success") { value(false) }
            jsonPath("$.error.code") { value("TOKEN_INVALID") }
        }
    }

    @Test
    fun `POST logout returns 204 No Content`() {
        justRun { revokeTokenUseCase.execute(any()) }

        mockMvc.post("/api/v1/auth/logout") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"refreshToken":"some-token"}"""
        }.andExpect {
            status { isNoContent() }
        }
    }
}
```

### Step 5.2: Verify RED

```bash
./gradlew test --tests "com.aibles.iam.authentication.api.AuthControllerTest"
# Expected: FAILED — "Unresolved reference: AuthController"
```

### Step 5.3: Create request DTOs

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/RefreshTokenRequest.kt
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class RefreshTokenRequest(@field:NotBlank val refreshToken: String)
```

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/LogoutRequest.kt
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class LogoutRequest(@field:NotBlank val refreshToken: String)
```

### Step 5.4: Create `AuthController.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/AuthController.kt
package com.aibles.iam.authentication.api

import com.aibles.iam.authentication.api.dto.LogoutRequest
import com.aibles.iam.authentication.api.dto.RefreshTokenRequest
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.shared.response.ApiResponse
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth")
class AuthController(
    private val refreshTokenUseCase: RefreshTokenUseCase,
    private val revokeTokenUseCase: RevokeTokenUseCase,
) {

    @PostMapping("/refresh")
    fun refresh(@Valid @RequestBody request: RefreshTokenRequest): ApiResponse<TokenResponse> {
        val result = refreshTokenUseCase.execute(RefreshTokenUseCase.Command(request.refreshToken))
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun logout(@Valid @RequestBody request: LogoutRequest) {
        revokeTokenUseCase.execute(RevokeTokenUseCase.Command(request.refreshToken))
    }
}
```

### Step 5.5: Verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authentication.api.AuthControllerTest"
# Expected: 3 tests pass

./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass
```

### Step 5.6: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): Auth REST controller with refresh and logout endpoints (Closes #<N>)"
git push -u origin feature/<N>-auth-controller
gh pr create --title "feat(authentication): Auth REST controller (refresh + logout)" \
  --base main --body "Closes #<N>"
gh pr merge <PR-number> --squash --delete-branch
git checkout main && git pull
```

---

## Sprint 3 Completion Checklist

Before declaring Sprint 3 done, verify:

```bash
# Full test suite
./gradlew test
# Expected: BUILD SUCCESSFUL — zero failures

# Generate RSA key pair and set in .env for manual smoke test
openssl genrsa -out /tmp/iam-private.pem 2048
openssl pkcs8 -topk8 -nocrypt -in /tmp/iam-private.pem -out /tmp/iam-pkcs8.pem
openssl rsa -in /tmp/iam-private.pem -pubout -out /tmp/iam-public.pem

# Set in .env (base64-encoded DER, no headers, no newlines):
JWT_PRIVATE_KEY=$(cat /tmp/iam-pkcs8.pem | grep -v "^-" | tr -d '\n')
JWT_PUBLIC_KEY=$(cat /tmp/iam-public.pem | grep -v "^-" | tr -d '\n')

# Start app
docker compose up -d
./gradlew bootRun &
sleep 15

# Health check
curl -s http://localhost:8080/actuator/health
# Expected: {"status":"UP"}

# Google OAuth2 flow (manual, requires real GOOGLE_CLIENT_ID/SECRET in .env):
# Open browser → http://localhost:8080/oauth2/authorization/google
# Complete Google sign-in → response body should be:
# { "success": true, "data": { "accessToken": "...", "refreshToken": "...", "expiresIn": 900 } }

# Test refresh endpoint with a real token:
ACCESS=<token-from-above>
REFRESH=<refresh-from-above>
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}" | jq .
# Expected: { "success": true, "data": { "accessToken": "...", "refreshToken": "...", ... } }

# Test logout:
curl -s -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}" -w "\nHTTP %{http_code}"
# Expected: HTTP 204

# Re-use refresh after logout → must fail:
curl -s -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\"}" | jq .
# Expected: { "success": false, "error": { "code": "TOKEN_INVALID", ... } }
```

## Known Issues to Watch

1. **`@WebMvcTest` + `SecurityConfig`:** `SecurityConfig` now injects `GoogleOAuth2SuccessHandler` and `JwtProperties`. Any `@WebMvcTest` test that doesn't use `addFilters = false` will try to instantiate these. All controller tests already have `@AutoConfigureMockMvc(addFilters = false)` so this is safe.

2. **`GlobalExceptionHandlerTest` mock updates:** When `AuthController` is added, `GlobalExceptionHandlerTest`'s `@WebMvcTest` will also scan it. Add `@MockkBean` for `RefreshTokenUseCase` and `RevokeTokenUseCase` there.

3. **RSA key pair generation for local dev:** Add the key generation commands to `.env.example` as comments. Never commit actual keys.

4. **`JwtProperties` bean in `@WebMvcTest`:** If a test fails because `JwtProperties` can't be autowired (empty string values fail key parsing in `SecurityConfig`), the `generateTestKey()` fallback in `SecurityConfig` handles this.
