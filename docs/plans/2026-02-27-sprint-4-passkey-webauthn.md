# Sprint 4: Passkey / WebAuthn Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Add WebAuthn/Passkey registration and authentication to the IAM service — users can register a passkey and log in with it, receiving the same JWT + refresh token pair as Google OAuth2.

**Architecture:** Five sequential GitHub issues. `PasskeyCredential` JPA entity maps to the existing `passkey_credentials` table (already in V1 migration — no new migration needed). `WebAuthnManager` from webauthn4j-core handles attestation/assertion cryptographic verification. `RedisChallengeStore` stores short-lived challenges (5-minute TTL, one-time use via getAndDelete). Use cases follow the same Command/Result/`@Component` pattern as the rest of the codebase. The REST controller adds passkey endpoints under `/api/v1/auth/passkey/`. SecurityConfig is updated in Task 5 to narrow the overly-broad `/api/v1/auth/**` permit-all.

**Tech Stack:** `webauthn4j-spring-security-core:0.11.0.RELEASE` (already in `build.gradle.kts` — transitively pulls `webauthn4j-core:~0.21`), Spring Data Redis / Lettuce (existing), Testcontainers `GenericContainer("redis:7-alpine")` (established pattern from Sprint 3), MockK for use case tests, `@WebMvcTest` + `addFilters = false` for controller tests, `SecurityMockMvcRequestPostProcessors.jwt()` for authenticated endpoint tests.

---

## Pre-work: Create GitHub Issues

```bash
gh issue create --title "feat: PasskeyCredential aggregate" \
  --body "JPA entity mapping passkey_credentials table. PasskeyCredentialRepository. Counter replay protection via verifyAndIncrementCounter()." \
  --label "sprint-4,authentication"

gh issue create --title "feat: WebAuthn4J config + Redis challenge store" \
  --body "WebAuthnManager bean. WebAuthnProperties (rpId, rpOrigin, rpName). RedisChallengeStore with 5-min TTL + one-time getAndDelete." \
  --label "sprint-4,authentication"

gh issue create --title "feat: Passkey registration use cases" \
  --body "RegisterPasskeyStartUseCase (generate challenge options). RegisterPasskeyFinishUseCase (verify attestation, save credential)." \
  --label "sprint-4,authentication"

gh issue create --title "feat: Passkey authentication use cases" \
  --body "AuthenticatePasskeyStartUseCase. AuthenticatePasskeyFinishUseCase (verify assertion, issue tokens). DeletePasskeyUseCase." \
  --label "sprint-4,authentication"

gh issue create --title "feat: Passkey REST API" \
  --body "PasskeyController: register/start, register/finish, authenticate/start, authenticate/finish, list credentials, delete credential. SecurityConfig narrowed." \
  --label "sprint-4,authentication,api"
```

Note the issue numbers (e.g. `#29`, `#30`, ...) — use them in all branch names and PR bodies below.

---

## Task 1: PasskeyCredential Aggregate

**GitHub Issue:** first issue above (e.g. `#29`)
**Branch:** `feature/<N>-passkey-credential`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredential.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialRepository.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialTest.kt`

### Step 1.1: Write failing tests (RED)

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialTest.kt
package com.aibles.iam.authentication.domain.passkey

import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class PasskeyCredentialTest {

    private fun credential(counter: Long = 0) = PasskeyCredential(
        userId = UUID.randomUUID(),
        credentialId = byteArrayOf(1, 2, 3),
        publicKeyCose = byteArrayOf(4, 5, 6),
        signCounter = counter,
    )

    @Test
    fun `verifyAndIncrementCounter accepts higher counter`() {
        val c = credential(5)
        c.verifyAndIncrementCounter(6)
        assertThat(c.signCounter).isEqualTo(6)
    }

    @Test
    fun `verifyAndIncrementCounter rejects equal counter (replay)`() {
        val ex = assertThrows<UnauthorizedException> { credential(5).verifyAndIncrementCounter(5) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }

    @Test
    fun `verifyAndIncrementCounter rejects lower counter (replay)`() {
        val ex = assertThrows<UnauthorizedException> { credential(5).verifyAndIncrementCounter(3) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }
}
```

### Step 1.2: Run to verify RED

```bash
source ~/.sdkman/bin/sdkman-init.sh && sdk use java 24.0.2-amzn
./gradlew test --tests "com.aibles.iam.authentication.domain.passkey.*"
# Expected: FAILED — "Unresolved reference: PasskeyCredential"
```

### Step 1.3: Create `PasskeyCredential.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredential.kt
package com.aibles.iam.authentication.domain.passkey

import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "passkey_credentials")
class PasskeyCredential(
    @Id val id: UUID = UUID.randomUUID(),
    @Column(name = "user_id", nullable = false) val userId: UUID,
    @Column(name = "credential_id", columnDefinition = "bytea", nullable = false, unique = true)
    var credentialId: ByteArray,
    @Column(name = "public_key_cose", columnDefinition = "bytea", nullable = false)
    var publicKeyCose: ByteArray,
    @Column(name = "sign_counter", nullable = false) var signCounter: Long = 0,
    @Column(name = "aaguid") var aaguid: UUID? = null,
    @Column(name = "display_name") var displayName: String? = null,
    @Column(name = "created_at", nullable = false) val createdAt: Instant = Instant.now(),
    @Column(name = "last_used_at") var lastUsedAt: Instant? = null,
) {
    // Required by JPA
    protected constructor() : this(userId = UUID.randomUUID(), credentialId = ByteArray(0), publicKeyCose = ByteArray(0))

    fun verifyAndIncrementCounter(newCounter: Long) {
        if (newCounter <= signCounter)
            throw UnauthorizedException("Counter replay detected", ErrorCode.PASSKEY_COUNTER_INVALID)
        signCounter = newCounter
    }
}
```

### Step 1.4: Create `PasskeyCredentialRepository.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialRepository.kt
package com.aibles.iam.authentication.domain.passkey

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface PasskeyCredentialRepository : JpaRepository<PasskeyCredential, UUID> {
    fun findByCredentialId(credentialId: ByteArray): PasskeyCredential?
    fun findAllByUserId(userId: UUID): List<PasskeyCredential>
}
```

### Step 1.5: Run to verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authentication.domain.passkey.*"
# Expected: BUILD SUCCESSFUL — 3 tests PASSED

./gradlew test
# Expected: BUILD SUCCESSFUL — all existing tests still pass
```

### Step 1.6: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): PasskeyCredential aggregate + counter replay protection (Closes #<N>)"
git push -u origin feature/<N>-passkey-credential
gh pr create --title "feat(authentication): PasskeyCredential aggregate" --body "Closes #<N>" --base main
gh pr merge <PR> --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 2: WebAuthn4J Config + Redis Challenge Store

**GitHub Issue:** second issue above (e.g. `#30`)
**Branch:** `feature/<N>-webauthn-config`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/shared/config/WebAuthnProperties.kt`
- Create: `src/main/kotlin/com/aibles/iam/shared/config/WebAuthnConfig.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/infra/RedisChallengeStore.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/infra/RedisChallengeStoreTest.kt`
- Modify: `src/main/kotlin/com/aibles/iam/IamApplication.kt` — add `WebAuthnProperties` to `@EnableConfigurationProperties`
- Modify: `src/main/resources/application.yml` — add `webauthn:` section

### Step 2.1: Write failing tests (RED)

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/infra/RedisChallengeStoreTest.kt
package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.containers.GenericContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.util.UUID

@Testcontainers
class RedisChallengeStoreTest {

    companion object {
        @Container
        @JvmStatic
        val redis: GenericContainer<*> = GenericContainer("redis:7-alpine")
            .withExposedPorts(6379)
    }

    private val template: StringRedisTemplate by lazy {
        val factory = LettuceConnectionFactory("localhost", redis.getMappedPort(6379))
        factory.afterPropertiesSet()
        StringRedisTemplate(factory).apply { afterPropertiesSet() }
    }

    private val store: RedisChallengeStore by lazy { RedisChallengeStore(template) }

    @AfterEach
    fun flush() {
        template.connectionFactory?.connection?.serverCommands()?.flushAll()
    }

    @Test
    fun `store and retrieve challenge succeeds once`() {
        val sessionId = UUID.randomUUID().toString()
        val challenge = "hello-challenge".toByteArray()

        store.storeChallenge(sessionId, challenge)
        val returned = store.getAndDeleteChallenge(sessionId)

        assertThat(returned).isEqualTo(challenge)
    }

    @Test
    fun `retrieving challenge twice throws BadRequestException with PASSKEY_CHALLENGE_EXPIRED`() {
        val sessionId = UUID.randomUUID().toString()
        store.storeChallenge(sessionId, "challenge".toByteArray())

        store.getAndDeleteChallenge(sessionId)  // first retrieval succeeds

        val ex = assertThrows<BadRequestException> {
            store.getAndDeleteChallenge(sessionId)  // second: must fail
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }

    @Test
    fun `getting non-existent challenge throws BadRequestException with PASSKEY_CHALLENGE_EXPIRED`() {
        val ex = assertThrows<BadRequestException> {
            store.getAndDeleteChallenge("no-such-session")
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }
}
```

### Step 2.2: Run to verify RED

```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisChallengeStoreTest"
# Expected: FAILED — "Unresolved reference: RedisChallengeStore"
```

### Step 2.3: Create `WebAuthnProperties.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/WebAuthnProperties.kt
package com.aibles.iam.shared.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties("webauthn")
data class WebAuthnProperties(
    val rpId: String = "localhost",
    val rpOrigin: String = "http://localhost:8080",
    val rpName: String = "IAM Service",
)
```

### Step 2.4: Create `WebAuthnConfig.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/shared/config/WebAuthnConfig.kt
package com.aibles.iam.shared.config

import com.webauthn4j.WebAuthnManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class WebAuthnConfig {
    @Bean
    fun webAuthnManager(): WebAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()
}
```

> **Note:** `createNonStrictWebAuthnManager()` skips attestation trust chain verification, which is correct for development and typical deployments (attestation is "none"). For high-assurance deployments, configure a custom WebAuthnManager with appropriate trust anchors.

### Step 2.5: Create `RedisChallengeStore.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/infra/RedisChallengeStore.kt
package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.Base64

@Component
class RedisChallengeStore(private val template: StringRedisTemplate) {

    fun storeChallenge(sessionId: String, challenge: ByteArray) {
        template.opsForValue().set(
            "wc:$sessionId",
            Base64.getEncoder().encodeToString(challenge),
            Duration.ofMinutes(5),
        )
    }

    fun getAndDeleteChallenge(sessionId: String): ByteArray {
        val encoded = template.opsForValue().getAndDelete("wc:$sessionId")
            ?: throw BadRequestException("WebAuthn challenge expired or not found", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
        return Base64.getDecoder().decode(encoded)
    }
}
```

### Step 2.6: Update `IamApplication.kt`

Change:
```kotlin
@EnableConfigurationProperties(JwtProperties::class)
```
To:
```kotlin
@EnableConfigurationProperties(JwtProperties::class, WebAuthnProperties::class)
```

### Step 2.7: Update `application.yml` — add webauthn section

```yaml
webauthn:
  rp-id: ${WEBAUTHN_RP_ID:localhost}
  rp-origin: ${WEBAUTHN_RP_ORIGIN:http://localhost:8080}
  rp-name: ${WEBAUTHN_RP_NAME:IAM Service}
```

### Step 2.8: Run to verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisChallengeStoreTest"
# Expected: BUILD SUCCESSFUL — 3 tests PASSED

./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass
```

### Step 2.9: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): WebAuthn4J config + Redis challenge store (Closes #<N>)"
git push -u origin feature/<N>-webauthn-config
gh pr create --title "feat(authentication): WebAuthn4J config + Redis challenge store" --body "Closes #<N>" --base main
gh pr merge <PR> --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 3: Passkey Registration Use Cases

**GitHub Issue:** third issue above (e.g. `#31`)
**Branch:** `feature/<N>-passkey-registration`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCaseTest.kt`

**Background on the WebAuthn registration flow:**
1. Client calls `register/start` → server generates a random 32-byte challenge, stores it in Redis under a new `sessionId`, returns `PublicKeyCredentialCreationOptions` JSON to the browser
2. Browser calls `navigator.credentials.create(options)` → user taps hardware key / FaceID → browser returns a `PublicKeyCredential` with `attestationObject` and `clientDataJSON` (both base64url-encoded)
3. Client calls `register/finish` → server decodes the bytes, calls `webAuthnManager.verify()` (validates the challenge, origin, signature), extracts the credential public key and stores it as `PasskeyCredential`

### Step 3.1: Write failing tests (RED)

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCaseTest.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class RegisterPasskeyStartUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test App")
    private val useCase = RegisterPasskeyStartUseCase(redisChallengeStore, props)

    @Test
    fun `execute returns sessionId and options with rpId and challenge`() {
        val challengeSlot = slot<ByteArray>()
        every { redisChallengeStore.storeChallenge(any(), capture(challengeSlot)) } just runs

        val userId = UUID.randomUUID()
        val result = useCase.execute(RegisterPasskeyStartUseCase.Command(userId, "user@test.com", "Test User"))

        assertThat(result.sessionId).isNotBlank()
        assertThat(result.rpId).isEqualTo("localhost")
        assertThat(result.challenge).isNotBlank()          // base64url-encoded challenge
        assertThat(result.userId).isEqualTo(userId.toString())
        assertThat(challengeSlot.captured).hasSize(32)     // 32 random bytes
    }
}
```

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCaseTest.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.webauthn4j.WebAuthnManager
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class RegisterPasskeyFinishUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val credentialRepository = mockk<PasskeyCredentialRepository>()
    private val webAuthnManager = mockk<WebAuthnManager>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test")
    private val useCase = RegisterPasskeyFinishUseCase(redisChallengeStore, credentialRepository, webAuthnManager, props)

    @Test
    fun `expired challenge propagates PASSKEY_CHALLENGE_EXPIRED`() {
        every { redisChallengeStore.getAndDeleteChallenge("session-1") } throws
            BadRequestException("Challenge expired", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)

        val ex = assertThrows<BadRequestException> {
            useCase.execute(RegisterPasskeyFinishUseCase.Command(
                userId = UUID.randomUUID(),
                sessionId = "session-1",
                clientDataJSON = "dGVzdA==",
                attestationObject = "dGVzdA==",
                displayName = null,
            ))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }

    @Test
    fun `webAuthnManager validation failure throws PASSKEY_ATTESTATION_FAILED`() {
        every { redisChallengeStore.getAndDeleteChallenge(any()) } returns ByteArray(32)
        every { webAuthnManager.verify(any(), any()) } throws
            RuntimeException("Attestation signature mismatch")

        val ex = assertThrows<BadRequestException> {
            useCase.execute(RegisterPasskeyFinishUseCase.Command(
                userId = UUID.randomUUID(),
                sessionId = "session-2",
                clientDataJSON = "dGVzdA==",
                attestationObject = "dGVzdA==",
                displayName = null,
            ))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_ATTESTATION_FAILED)
    }
}
```

### Step 3.2: Run to verify RED

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.RegisterPasskey*"
# Expected: FAILED — "Unresolved reference: RegisterPasskeyStartUseCase"
```

### Step 3.3: Create `RegisterPasskeyStartUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class RegisterPasskeyStartUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val props: WebAuthnProperties,
) {
    data class Command(val userId: UUID, val userEmail: String, val displayName: String?)
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val userId: String,        // base64url userId for browser
        val userEmail: String,
        val userDisplayName: String?,
        val challenge: String,     // base64url challenge
        val pubKeyCredParams: List<Map<String, Any>> = listOf(
            mapOf("type" to "public-key", "alg" to -7),    // ES256
            mapOf("type" to "public-key", "alg" to -257),  // RS256
        ),
        val timeout: Int = 60_000,
        val attestation: String = "none",
    )

    fun execute(command: Command): Result {
        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        redisChallengeStore.storeChallenge(sessionId, challengeBytes)

        return Result(
            sessionId = sessionId,
            rpId = props.rpId,
            rpName = props.rpName,
            userId = Base64.getUrlEncoder().withoutPadding().encodeToString(command.userId.toString().toByteArray()),
            userEmail = command.userEmail,
            userDisplayName = command.displayName,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }
}
```

### Step 3.4: Create `RegisterPasskeyFinishUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import org.springframework.stereotype.Component
import java.util.Base64
import java.util.UUID

@Component
class RegisterPasskeyFinishUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val credentialRepository: PasskeyCredentialRepository,
    private val webAuthnManager: WebAuthnManager,
    private val props: WebAuthnProperties,
) {
    private val objectConverter = ObjectConverter()

    data class Command(
        val userId: UUID,
        val sessionId: String,
        val clientDataJSON: String,    // base64url from browser
        val attestationObject: String, // base64url from browser
        val displayName: String?,
    )

    fun execute(command: Command) {
        // Step 1: retrieve and consume challenge (throws PASSKEY_CHALLENGE_EXPIRED if missing)
        val challenge = redisChallengeStore.getAndDeleteChallenge(command.sessionId)

        // Step 2: decode browser response bytes (browsers send base64url without padding)
        val decoder = Base64.getUrlDecoder()
        val clientDataBytes = decoder.decode(command.clientDataJSON.padBase64Url())
        val attestationBytes = decoder.decode(command.attestationObject.padBase64Url())

        // Step 3: build webauthn4j request + parameters
        val registrationRequest = RegistrationRequest(attestationBytes, clientDataBytes)
        val serverProperty = ServerProperty(
            Origin.create(props.rpOrigin),
            props.rpId,
            DefaultChallenge(challenge),
            null,
        )
        val registrationParameters = RegistrationParameters(serverProperty, null, false, true)

        // Step 4: verify — throws RuntimeException subclasses on failure
        val data = try {
            webAuthnManager.verify(registrationRequest, registrationParameters)
        } catch (e: RuntimeException) {
            throw BadRequestException("Passkey attestation failed: ${e.message}", ErrorCode.PASSKEY_ATTESTATION_FAILED)
        }

        // Step 5: extract credential data from verification result
        val authData = data.attestationObject!!.authenticatorData!!
        val credData = authData.attestedCredentialData!!
        val coseKeyBytes = objectConverter.cborConverter.writeValueAsBytes(credData.coseKey)
        val aaguid: UUID? = credData.aaguid?.value?.let {
            try { UUID.fromString(it.toString()) } catch (e: Exception) { null }
        }

        // Step 6: save credential
        credentialRepository.save(
            PasskeyCredential(
                userId = command.userId,
                credentialId = credData.credentialId,
                publicKeyCose = coseKeyBytes,
                signCounter = authData.signCount,
                aaguid = aaguid,
                displayName = command.displayName,
            )
        )
    }

    // base64url strings from browsers may lack padding — add it before decoding
    private fun String.padBase64Url(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}
```

> **webauthn4j API note:** The imports above use the standard `com.webauthn4j.*` package layout from `webauthn4j-core` 0.21.x. If the project's transitive version differs, check the import paths via `./gradlew dependencies --configuration runtimeClasspath | grep webauthn4j`. The key classes are: `WebAuthnManager`, `RegistrationRequest`, `RegistrationParameters`, `ServerProperty`, `Origin`, `DefaultChallenge`, `ObjectConverter`.
>
> `AAGUID.value` may be a `UUID` or a `String` depending on the webauthn4j version — if it's a `String` already parseable as UUID, remove the `toString()` call. If it's raw bytes use `null` as fallback.

### Step 3.5: Run to verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.RegisterPasskey*"
# Expected: BUILD SUCCESSFUL — 3 tests PASSED (1 start + 2 finish)

./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass
```

### Step 3.6: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): Passkey registration use cases (Closes #<N>)"
git push -u origin feature/<N>-passkey-registration
gh pr create --title "feat(authentication): Passkey registration use cases" --body "Closes #<N>" --base main
gh pr merge <PR> --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 4: Passkey Authentication Use Cases

**GitHub Issue:** fourth issue above (e.g. `#32`)
**Branch:** `feature/<N>-passkey-auth-usecases`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyStartUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/DeletePasskeyUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyStartUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/DeletePasskeyUseCaseTest.kt`

**Background on the authentication flow:**
1. Client calls `authenticate/start` (no user required — this is the login) → server generates challenge, returns `PublicKeyCredentialRequestOptions`
2. Browser calls `navigator.credentials.get(options)` → user authenticates → returns assertion with `credentialId`, `authenticatorData`, `clientDataJSON`, `signature`
3. Client calls `authenticate/finish` → server finds stored credential by `credentialId`, verifies the assertion signature, checks counter, issues JWT + refresh token

### Step 4.1: Write failing tests (RED)

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyStartUseCaseTest.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.slot
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AuthenticatePasskeyStartUseCaseTest {

    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test")
    private val useCase = AuthenticatePasskeyStartUseCase(redisChallengeStore, props)

    @Test
    fun `execute returns sessionId, rpId, and 32-byte challenge`() {
        val challengeSlot = slot<ByteArray>()
        every { redisChallengeStore.storeChallenge(any(), capture(challengeSlot)) } just runs

        val result = useCase.execute()

        assertThat(result.sessionId).isNotBlank()
        assertThat(result.rpId).isEqualTo("localhost")
        assertThat(result.challenge).isNotBlank()
        assertThat(challengeSlot.captured).hasSize(32)
    }
}
```

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCaseTest.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserStatus
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.error.UnauthorizedException
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.data.AuthenticationData
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class AuthenticatePasskeyFinishUseCaseTest {

    private val credentialRepository = mockk<PasskeyCredentialRepository>()
    private val redisChallengeStore = mockk<RedisChallengeStore>()
    private val webAuthnManager = mockk<WebAuthnManager>()
    private val getUserUseCase = mockk<GetUserUseCase>()
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val props = WebAuthnProperties(rpId = "localhost", rpOrigin = "http://localhost:8080", rpName = "Test")

    private val useCase = AuthenticatePasskeyFinishUseCase(
        credentialRepository, redisChallengeStore, webAuthnManager, getUserUseCase, issueTokenUseCase, props,
    )

    private val userId = UUID.randomUUID()
    private val credId = byteArrayOf(1, 2, 3)
    private val storedCredential = PasskeyCredential(
        userId = userId,
        credentialId = credId,
        publicKeyCose = byteArrayOf(4, 5, 6),
        signCounter = 5L,
    )

    private fun command(credentialId: String = "AQID", sessionId: String = "sess") =
        AuthenticatePasskeyFinishUseCase.Command(
            credentialId = credentialId,
            sessionId = sessionId,
            clientDataJSON = "dGVzdA==",
            authenticatorData = "dGVzdA==",
            signature = "dGVzdA==",
            userHandle = null,
        )

    @Test
    fun `happy path returns access and refresh tokens`() {
        val mockAuthData = mockk<AuthenticationData>(relaxed = true)
        every { mockAuthData.authenticatorData.signCount } returns 6L

        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge("sess") } returns ByteArray(32)
        every { webAuthnManager.verify(any(), any()) } returns mockAuthData
        every { credentialRepository.save(any()) } returns storedCredential
        val user = User.create("user@test.com", "Test User")
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(command())

        assertThat(result.accessToken).isEqualTo("access")
        assertThat(result.refreshToken).isEqualTo("refresh")
    }

    @Test
    fun `unknown credentialId throws PASSKEY_NOT_FOUND`() {
        every { credentialRepository.findByCredentialId(any()) } returns null

        val ex = assertThrows<NotFoundException> { useCase.execute(command()) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_NOT_FOUND)
    }

    @Test
    fun `expired challenge throws PASSKEY_CHALLENGE_EXPIRED`() {
        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge(any()) } throws
            BadRequestException("Expired", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)

        val ex = assertThrows<BadRequestException> { useCase.execute(command()) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
    }

    @Test
    fun `counter replay detected by webauthn4j throws PASSKEY_COUNTER_INVALID`() {
        every { credentialRepository.findByCredentialId(any()) } returns storedCredential
        every { redisChallengeStore.getAndDeleteChallenge(any()) } returns ByteArray(32)
        // webauthn4j throws BadSignCountException on counter replay
        every { webAuthnManager.verify(any(), any()) } throws
            com.webauthn4j.exception.BadSignCountException("Counter replay")

        val ex = assertThrows<UnauthorizedException> { useCase.execute(command()) }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_COUNTER_INVALID)
    }
}
```

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/usecase/DeletePasskeyUseCaseTest.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.runs
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.UUID

class DeletePasskeyUseCaseTest {

    private val credentialRepository = mockk<PasskeyCredentialRepository>()
    private val useCase = DeletePasskeyUseCase(credentialRepository)

    private val userId = UUID.randomUUID()
    private val credentialId = UUID.randomUUID()

    @Test
    fun `happy path deletes existing credential`() {
        val credential = PasskeyCredential(
            id = credentialId, userId = userId,
            credentialId = byteArrayOf(1, 2), publicKeyCose = byteArrayOf(3, 4),
        )
        every { credentialRepository.findById(credentialId) } returns java.util.Optional.of(credential)
        every { credentialRepository.delete(credential) } just runs

        useCase.execute(DeletePasskeyUseCase.Command(userId, credentialId))

        verify(exactly = 1) { credentialRepository.delete(credential) }
    }

    @Test
    fun `unknown credential throws PASSKEY_NOT_FOUND`() {
        every { credentialRepository.findById(credentialId) } returns java.util.Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(DeletePasskeyUseCase.Command(userId, credentialId))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_NOT_FOUND)
    }

    @Test
    fun `credential belonging to different user throws PASSKEY_NOT_FOUND`() {
        val otherUser = UUID.randomUUID()
        val credential = PasskeyCredential(
            id = credentialId, userId = otherUser,
            credentialId = byteArrayOf(1, 2), publicKeyCose = byteArrayOf(3, 4),
        )
        every { credentialRepository.findById(credentialId) } returns java.util.Optional.of(credential)

        val ex = assertThrows<NotFoundException> {
            useCase.execute(DeletePasskeyUseCase.Command(userId, credentialId))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.PASSKEY_NOT_FOUND)
    }
}
```

### Step 4.2: Run to verify RED

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.AuthenticatePasskey*"
./gradlew test --tests "com.aibles.iam.authentication.usecase.DeletePasskeyUseCaseTest"
# Expected: FAILED — "Unresolved reference"
```

### Step 4.3: Create `AuthenticatePasskeyStartUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyStartUseCase.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.shared.config.WebAuthnProperties
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class AuthenticatePasskeyStartUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val props: WebAuthnProperties,
) {
    data class Result(
        val sessionId: String,
        val rpId: String,
        val challenge: String,  // base64url
        val timeout: Int = 60_000,
        val userVerification: String = "preferred",
    )

    fun execute(): Result {
        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        redisChallengeStore.storeChallenge(sessionId, challengeBytes)
        return Result(
            sessionId = sessionId,
            rpId = props.rpId,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }
}
```

### Step 4.4: Create `AuthenticatePasskeyFinishUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.config.WebAuthnProperties
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.error.UnauthorizedException
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.exception.BadSignCountException
import com.webauthn4j.server.ServerProperty
import org.springframework.stereotype.Component
import java.time.Instant
import java.util.Base64
import java.util.UUID

@Component
class AuthenticatePasskeyFinishUseCase(
    private val credentialRepository: PasskeyCredentialRepository,
    private val redisChallengeStore: RedisChallengeStore,
    private val webAuthnManager: WebAuthnManager,
    private val getUserUseCase: GetUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
    private val props: WebAuthnProperties,
) {
    private val objectConverter = ObjectConverter()

    data class Command(
        val credentialId: String,   // base64url from browser
        val sessionId: String,
        val clientDataJSON: String,     // base64url
        val authenticatorData: String,  // base64url
        val signature: String,          // base64url
        val userHandle: String?,        // base64url, optional
    )
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val decoder = Base64.getUrlDecoder()

        // Step 1: look up stored credential
        val credIdBytes = decoder.decode(command.credentialId.padBase64Url())
        val credential = credentialRepository.findByCredentialId(credIdBytes)
            ?: throw NotFoundException("Passkey credential not found", ErrorCode.PASSKEY_NOT_FOUND)

        // Step 2: retrieve and consume challenge
        val challenge = redisChallengeStore.getAndDeleteChallenge(command.sessionId)

        // Step 3: reconstruct credential record for webauthn4j verification
        val coseKey = objectConverter.cborConverter.readValue(
            credential.publicKeyCose,
            com.webauthn4j.data.attestation.authenticator.COSEKey::class.java,
        )
        val aaguid = credential.aaguid?.let { AAGUID(it) } ?: AAGUID.ZERO
        val attestedCredentialData = AttestedCredentialData(aaguid, credential.credentialId, coseKey)
        val credRecord = CredentialRecordImpl(
            /* attestationStatement */ null,
            /* aaguid */ aaguid,
            /* counter */ credential.signCounter,
            /* uvInitialized */ false,
            /* backupEligible */ null,
            /* backupState */ null,
            /* attestedCredentialData */ attestedCredentialData,
            /* authenticatorExtensions */ null,
            /* authenticatorTransports */ null,
            /* clientExtensions */ null,
        )

        // Step 4: build authentication request + parameters
        val authRequest = AuthenticationRequest(
            credential.credentialId,
            command.userHandle?.let { decoder.decode(it.padBase64Url()) },
            decoder.decode(command.authenticatorData.padBase64Url()),
            decoder.decode(command.clientDataJSON.padBase64Url()),
            decoder.decode(command.signature.padBase64Url()),
        )
        val serverProperty = ServerProperty(
            Origin.create(props.rpOrigin),
            props.rpId,
            DefaultChallenge(challenge),
            null,
        )
        val authParameters = AuthenticationParameters(serverProperty, credRecord, false, true)

        // Step 5: verify assertion
        val authData = try {
            webAuthnManager.verify(authRequest, authParameters)
        } catch (e: BadSignCountException) {
            throw UnauthorizedException("Counter replay detected", ErrorCode.PASSKEY_COUNTER_INVALID)
        } catch (e: RuntimeException) {
            throw UnauthorizedException("Passkey assertion verification failed", ErrorCode.TOKEN_INVALID)
        }

        // Step 6: update counter and last-used timestamp
        credential.verifyAndIncrementCounter(authData.authenticatorData.signCount)
        credential.lastUsedAt = Instant.now()
        credentialRepository.save(credential)

        // Step 7: load user, check active, issue tokens
        val user = getUserUseCase.execute(GetUserUseCase.Query(credential.userId))
        if (!user.isActive()) throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }

    private fun String.padBase64Url(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}
```

> **webauthn4j API note on `CredentialRecordImpl`:** The constructor above is for `webauthn4j-core` ~0.21.x. If it doesn't compile, check the actual constructor with your IDE or run `./gradlew dependencies --configuration runtimeClasspath | grep webauthn4j` to find the bundled core version, then look up `CredentialRecordImpl` in its sources. An alternative: use `AuthenticatorImpl` (deprecated alias that may still exist) or an anonymous `CredentialRecord` implementation.
>
> **Note on `AAGUID(UUID)`:** If `AAGUID` doesn't accept a `UUID` directly, use `AAGUID(credential.aaguid.toString())` or `AAGUID(credential.aaguid!!.toString().replace("-","").let { java.util.HexFormat.of().parseHex(it) })` depending on the version. If `AAGUID.ZERO` isn't available, use `AAGUID(UUID(0, 0))`.
>
> **Note on `COSEKey` import:** `com.webauthn4j.data.attestation.authenticator.COSEKey` is an interface. `objectConverter.cborConverter.readValue()` will deserialize to the concrete COSE key type automatically.

### Step 4.5: Create `DeletePasskeyUseCase.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/usecase/DeletePasskeyUseCase.kt
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class DeletePasskeyUseCase(private val credentialRepository: PasskeyCredentialRepository) {
    data class Command(val userId: UUID, val credentialId: UUID)

    fun execute(command: Command) {
        val credential = credentialRepository.findById(command.credentialId)
            .filter { it.userId == command.userId }
            .orElseThrow { NotFoundException("Passkey credential not found", ErrorCode.PASSKEY_NOT_FOUND) }
        credentialRepository.delete(credential)
    }
}
```

### Step 4.6: Run to verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.*"
# Expected: all new tests pass

./gradlew test
# Expected: BUILD SUCCESSFUL
```

### Step 4.7: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): Passkey authentication use cases + delete (Closes #<N>)"
git push -u origin feature/<N>-passkey-auth-usecases
gh pr create --title "feat(authentication): Passkey authentication use cases" --body "Closes #<N>" --base main
gh pr merge <PR> --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 5: Passkey REST Controller

**GitHub Issue:** fifth issue above (e.g. `#33`)
**Branch:** `feature/<N>-passkey-controller`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterStartRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterFinishRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/AuthenticateStartRequest.kt` (empty body — no fields needed)
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/AuthenticateFinishRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/PasskeyCredentialResponse.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/api/PasskeyControllerTest.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt` — narrow `/api/v1/auth/**` permit-all
- Modify: `src/test/kotlin/com/aibles/iam/identity/api/UsersControllerTest.kt` — add 5 new `@MockkBean`s
- Modify: `src/test/kotlin/com/aibles/iam/authentication/api/AuthControllerTest.kt` — add 5 new `@MockkBean`s
- Modify: `src/test/kotlin/com/aibles/iam/shared/error/GlobalExceptionHandlerTest.kt` — add 5 new `@MockkBean`s

**Endpoints:**
```
POST /api/v1/auth/passkey/register/start    ← requires JWT auth (registered user adds a passkey)
POST /api/v1/auth/passkey/register/finish   ← requires JWT auth
POST /api/v1/auth/passkey/authenticate/start ← public (login flow)
POST /api/v1/auth/passkey/authenticate/finish ← public (login flow, returns token pair)
GET  /api/v1/auth/passkey/credentials        ← requires JWT auth (list user's passkeys)
DELETE /api/v1/auth/passkey/credentials/{id} ← requires JWT auth
```

### Step 5.1: Write failing tests (RED)

```kotlin
// src/test/kotlin/com/aibles/iam/authentication/api/PasskeyControllerTest.kt
package com.aibles.iam.authentication.api

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
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
import com.aibles.iam.shared.error.NotFoundException
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import io.mockk.just
import io.mockk.justRun
import io.mockk.runs
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.delete
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import java.util.UUID

@WebMvcTest
@Import(GlobalExceptionHandler::class, PasskeyController::class)
@AutoConfigureMockMvc(addFilters = false)
class PasskeyControllerTest {

    @Autowired lateinit var mockMvc: MockMvc

    // PasskeyController deps
    @MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
    @MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
    @MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
    @MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
    @MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase

    // AuthController deps (scanned by @WebMvcTest)
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase

    // UsersController deps (scanned by @WebMvcTest)
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase

    private val userId = UUID.randomUUID()

    @Test
    fun `POST register-start returns 200 with sessionId and options`() {
        every { registerPasskeyStartUseCase.execute(any()) } returns
            RegisterPasskeyStartUseCase.Result(
                sessionId = "sess-1", rpId = "localhost", rpName = "Test",
                userId = userId.toString(), userEmail = "user@test.com", userDisplayName = null,
                challenge = "Y2hhbGxlbmdl",
            )

        mockMvc.post("/api/v1/auth/passkey/register/start") {
            with(jwt().jwt { it.subject(userId.toString()) })
            contentType = MediaType.APPLICATION_JSON
            content = """{"displayName": "My Key"}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.sessionId") { value("sess-1") }
            jsonPath("$.data.challenge") { value("Y2hhbGxlbmdl") }
        }
    }

    @Test
    fun `POST register-finish returns 200`() {
        justRun { registerPasskeyFinishUseCase.execute(any()) }

        mockMvc.post("/api/v1/auth/passkey/register/finish") {
            with(jwt().jwt { it.subject(userId.toString()) })
            contentType = MediaType.APPLICATION_JSON
            content = """{"sessionId":"s","clientDataJSON":"dA==","attestationObject":"dA=="}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
        }
    }

    @Test
    fun `POST authenticate-start returns 200 without auth`() {
        every { authenticatePasskeyStartUseCase.execute() } returns
            AuthenticatePasskeyStartUseCase.Result(sessionId = "sess-2", rpId = "localhost", challenge = "Y2g=")

        mockMvc.post("/api/v1/auth/passkey/authenticate/start") {
            contentType = MediaType.APPLICATION_JSON
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.sessionId") { value("sess-2") }
        }
    }

    @Test
    fun `POST authenticate-finish returns 200 with token pair`() {
        every { authenticatePasskeyFinishUseCase.execute(any()) } returns
            AuthenticatePasskeyFinishUseCase.Result("access-tok", "refresh-tok", 900)

        mockMvc.post("/api/v1/auth/passkey/authenticate/finish") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"credentialId":"AQID","sessionId":"s","clientDataJSON":"dA==","authenticatorData":"dA==","signature":"dA=="}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.accessToken") { value("access-tok") }
            jsonPath("$.data.refreshToken") { value("refresh-tok") }
        }
    }

    @Test
    fun `GET credentials returns list of passkeys`() {
        val cred = PasskeyCredential(userId = userId, credentialId = byteArrayOf(1), publicKeyCose = byteArrayOf(2))
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns
            com.aibles.iam.identity.domain.user.User.create("u@t.com", "User")
        // PasskeyController will call a dedicated use case or repository — see controller impl below

        // Minimal happy path: 200 with success
        mockMvc.get("/api/v1/auth/passkey/credentials") {
            with(jwt().jwt { it.subject(userId.toString()) })
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `DELETE credentials-{id} not found returns 404`() {
        val credId = UUID.randomUUID()
        every { deletePasskeyUseCase.execute(DeletePasskeyUseCase.Command(userId, credId)) } throws
            NotFoundException("Not found", ErrorCode.PASSKEY_NOT_FOUND)

        mockMvc.delete("/api/v1/auth/passkey/credentials/$credId") {
            with(jwt().jwt { it.subject(userId.toString()) })
        }.andExpect {
            status { isNotFound() }
            jsonPath("$.error.code") { value("PASSKEY_NOT_FOUND") }
        }
    }
}
```

> **Note on `GET /credentials` test:** The `PasskeyController` will need either a dedicated `ListPasskeyCredentialsUseCase` or can call `PasskeyCredentialRepository` directly via a use case. For simplicity, we'll add a `listCredentials` method to `GetPasskeyCredentialsUseCase` or just inject the repository. See controller implementation below.

### Step 5.2: Run to verify RED

```bash
./gradlew test --tests "com.aibles.iam.authentication.api.PasskeyControllerTest"
# Expected: FAILED — "Unresolved reference: PasskeyController"
```

### Step 5.3: Create DTOs

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterStartRequest.kt
package com.aibles.iam.authentication.api.dto

data class RegisterStartRequest(val displayName: String? = null)
```

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterFinishRequest.kt
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class RegisterFinishRequest(
    @field:NotBlank val sessionId: String,
    @field:NotBlank val clientDataJSON: String,
    @field:NotBlank val attestationObject: String,
    val displayName: String? = null,
)
```

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/AuthenticateFinishRequest.kt
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.NotBlank

data class AuthenticateFinishRequest(
    @field:NotBlank val credentialId: String,
    @field:NotBlank val sessionId: String,
    @field:NotBlank val clientDataJSON: String,
    @field:NotBlank val authenticatorData: String,
    @field:NotBlank val signature: String,
    val userHandle: String? = null,
)
```

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/dto/PasskeyCredentialResponse.kt
package com.aibles.iam.authentication.api.dto

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import java.time.Instant
import java.util.Base64
import java.util.UUID

data class PasskeyCredentialResponse(
    val id: UUID,
    val credentialId: String,  // base64url
    val displayName: String?,
    val createdAt: Instant,
    val lastUsedAt: Instant?,
) {
    companion object {
        fun from(cred: PasskeyCredential) = PasskeyCredentialResponse(
            id = cred.id,
            credentialId = Base64.getUrlEncoder().withoutPadding().encodeToString(cred.credentialId),
            displayName = cred.displayName,
            createdAt = cred.createdAt,
            lastUsedAt = cred.lastUsedAt,
        )
    }
}
```

### Step 5.4: Create `PasskeyController.kt`

```kotlin
// src/main/kotlin/com/aibles/iam/authentication/api/PasskeyController.kt
package com.aibles.iam.authentication.api

import com.aibles.iam.authentication.api.dto.AuthenticateFinishRequest
import com.aibles.iam.authentication.api.dto.PasskeyCredentialResponse
import com.aibles.iam.authentication.api.dto.RegisterFinishRequest
import com.aibles.iam.authentication.api.dto.RegisterStartRequest
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.shared.response.ApiResponse
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/auth/passkey")
class PasskeyController(
    private val registerPasskeyStartUseCase: RegisterPasskeyStartUseCase,
    private val registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase,
    private val authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase,
    private val authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase,
    private val deletePasskeyUseCase: DeletePasskeyUseCase,
    private val credentialRepository: PasskeyCredentialRepository,
    private val getUserUseCase: GetUserUseCase,
) {

    @PostMapping("/register/start")
    fun registerStart(
        @AuthenticationPrincipal principal: Jwt,
        @RequestBody request: RegisterStartRequest,
    ): ApiResponse<RegisterPasskeyStartUseCase.Result> {
        val userId = UUID.fromString(principal.subject)
        val user = getUserUseCase.execute(GetUserUseCase.Query(userId))
        val result = registerPasskeyStartUseCase.execute(
            RegisterPasskeyStartUseCase.Command(userId, user.email, request.displayName)
        )
        return ApiResponse.ok(result)
    }

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
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/authenticate/start")
    fun authenticateStart(): ApiResponse<AuthenticatePasskeyStartUseCase.Result> =
        ApiResponse.ok(authenticatePasskeyStartUseCase.execute())

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
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }

    @GetMapping("/credentials")
    fun listCredentials(
        @AuthenticationPrincipal principal: Jwt,
    ): ApiResponse<List<PasskeyCredentialResponse>> {
        val userId = UUID.fromString(principal.subject)
        val credentials = credentialRepository.findAllByUserId(userId)
            .map { PasskeyCredentialResponse.from(it) }
        return ApiResponse.ok(credentials)
    }

    @DeleteMapping("/credentials/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteCredential(
        @AuthenticationPrincipal principal: Jwt,
        @PathVariable id: UUID,
    ) {
        val userId = UUID.fromString(principal.subject)
        deletePasskeyUseCase.execute(DeletePasskeyUseCase.Command(userId, id))
    }
}
```

> **Note:** `PasskeyController` injects `PasskeyCredentialRepository` directly for the list endpoint. This is pragmatic for a simple list-all-by-user operation. If the list endpoint grows complex (pagination, filtering), extract it to a `GetPasskeyCredentialsUseCase`.
>
> **Note on `ApiResponse<Unit>`:** The register/finish endpoint returns `ApiResponse.ok(Unit)` which serializes as `{"success":true,"data":{},"error":null,"timestamp":"..."}`. If you want it to return 204, annotate with `@ResponseStatus(HttpStatus.NO_CONTENT)` and return `Unit` directly (not wrapped).

### Step 5.5: Update `SecurityConfig.kt` — narrow the permit-all

Replace the current requestMatchers block:
```kotlin
// BEFORE (overly broad):
.requestMatchers(
    "/oauth2/**", "/login/**",
    "/api/v1/auth/**",      ← this permits /api/v1/auth/passkey/register/** too
    "/actuator/**",
    "/swagger-ui/**", "/v3/api-docs/**",
).permitAll()
```

With:
```kotlin
// AFTER (specific paths only):
.requestMatchers(
    "/oauth2/**", "/login/**",
    "/api/v1/auth/refresh",
    "/api/v1/auth/logout",
    "/api/v1/auth/passkey/authenticate/start",
    "/api/v1/auth/passkey/authenticate/finish",
    "/actuator/**",
    "/swagger-ui/**", "/v3/api-docs/**",
).permitAll()
```

This ensures `/api/v1/auth/passkey/register/**` and `/api/v1/auth/passkey/credentials/**` require a valid JWT.

### Step 5.6: Fix existing tests — add `@MockkBean`s for new PasskeyController deps

`PasskeyController` injects 7 dependencies. Once it's in the `@WebMvcTest` scan, every other `@WebMvcTest` class needs all 7 mocked. Add these `@MockkBean` fields to `UsersControllerTest`, `AuthControllerTest`, and `GlobalExceptionHandlerTest`:

```kotlin
// Add to each of the three existing test classes:
@MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
@MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
@MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
@MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
@MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase
```

`PasskeyController` also injects `PasskeyCredentialRepository` and `GetUserUseCase`. `GetUserUseCase` is already mocked in `UsersControllerTest` and `GlobalExceptionHandlerTest`. `PasskeyCredentialRepository` is NOT a `@Component`/`@Service` in the web layer scan (it's a JPA repository), but since we're using `@WebMvcTest` it may still be auto-detected if Spring tries to create `PasskeyController`. The safest approach: add `@MockkBean lateinit var passkeyCredentialRepository: PasskeyCredentialRepository` to **all four** test classes (including `PasskeyControllerTest`).

The imports for the new `@MockkBean`s:
```kotlin
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
```

> **Pattern reminder:** Every time a new `@RestController` is added, all existing `@WebMvcTest` classes need `@MockkBean` for all that controller's constructor dependencies. This is the established pattern in this codebase.

### Step 5.7: Fix `GET /credentials` test

The test for `GET /credentials` in step 5.1 calls `getUserUseCase` which isn't needed (controller directly calls the repository). Update the test:

```kotlin
@Test
fun `GET credentials returns list of passkeys`() {
    every { credentialRepository.findAllByUserId(userId) } returns emptyList()

    mockMvc.get("/api/v1/auth/passkey/credentials") {
        with(jwt().jwt { it.subject(userId.toString()) })
    }.andExpect {
        status { isOk() }
        jsonPath("$.success") { value(true) }
        jsonPath("$.data") { isArray() }
    }
}
```

Add `@MockkBean lateinit var credentialRepository: PasskeyCredentialRepository` to `PasskeyControllerTest`.

### Step 5.8: Run to verify GREEN

```bash
./gradlew test --tests "com.aibles.iam.authentication.api.PasskeyControllerTest"
# Expected: BUILD SUCCESSFUL — 6 tests pass

./gradlew test
# Expected: BUILD SUCCESSFUL — all tests pass (no regressions in UsersControllerTest, AuthControllerTest, GlobalExceptionHandlerTest)
```

If you see `UnsatisfiedDependencyException` about `PasskeyCredentialRepository` or any passkey use case, it means one of the three existing test classes is missing the new `@MockkBean`. Fix by adding the missing ones.

### Step 5.9: Commit and merge

```bash
git add src/
git commit -m "feat(authentication): Passkey REST controller + SecurityConfig narrowed (Closes #<N>)"
git push -u origin feature/<N>-passkey-controller
gh pr create --title "feat(authentication): Passkey REST controller" --body "Closes #<N>" --base main
gh pr merge <PR> --squash --delete-branch
git checkout main && git pull origin main
```

---

## Sprint 4 Completion Checklist

```bash
# Full test suite
./gradlew test
# Expected: BUILD SUCCESSFUL — zero failures

# Verify test count (should be substantially more than Sprint 3's 52)
find build/test-results -name "*.xml" | xargs grep -h "testcase" | wc -l
```

**Definition of Done:**
- [ ] 3 `PasskeyCredentialTest` tests pass (counter replay protection)
- [ ] 3 `RedisChallengeStoreTest` tests pass (one-time challenge consumption)
- [ ] `RegisterPasskeyStartUseCaseTest`: challenge stored, options returned
- [ ] `RegisterPasskeyFinishUseCaseTest`: expired challenge + attestation failure paths
- [ ] `AuthenticatePasskeyStartUseCaseTest`: challenge stored, options returned
- [ ] `AuthenticatePasskeyFinishUseCaseTest`: happy path, not-found, expired challenge, counter replay
- [ ] `DeletePasskeyUseCaseTest`: happy path, not-found, wrong-user
- [ ] `PasskeyControllerTest`: all 6 endpoints respond correctly
- [ ] Existing tests still pass (no regressions from `@MockkBean` additions)
- [ ] `SecurityConfig` narrows `/api/v1/auth/**` permit-all to specific paths

---

## webauthn4j Version Troubleshooting

Run this to find the actual webauthn4j-core version bundled with the spring-security wrapper:

```bash
./gradlew dependencies --configuration runtimeClasspath | grep webauthn4j
```

If the core version is different from ~0.21, check these class names:
- `CredentialRecordImpl` → may be `AuthenticatorImpl` in older versions
- `com.webauthn4j.credential.CredentialRecord` → may be `com.webauthn4j.authenticator.Authenticator`
- `AAGUID(uuid)` constructor → check if it takes `UUID`, `String`, or `byte[]`
- `com.webauthn4j.exception.BadSignCountException` → may be `MaliciousCounterValueException`

If `RegistrationParameters` constructor signature differs:
```bash
# Find the actual class in the JAR
find ~/.gradle -name "webauthn4j-core-*.jar" | head -1 | xargs jar tf | grep RegistrationParameters
```
