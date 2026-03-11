# Email + Passkey Registration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow users with an independent email (no Google account) to sign up and register a passkey in a single public flow.

**Architecture:** Four new public endpoints under `/api/v1/auth/register/`. Generalize `RedisOtpStore` to support scoped keys (`OtpScope` enum) so both existing passkey-reg and new signup flows share one store. Extract shared WebAuthn ceremony logic into `WebAuthnCeremonyService`. New use cases compose existing infra (EmailService, CreateUserUseCase, IssueTokenUseCase).

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Spring Data Redis (Lettuce), webauthn4j, JUnit 5, MockK, Testcontainers (Redis)

---

### Workflow Setup

**Before Task 1 — create the feature branch:**

```bash
git checkout main
git pull origin main
git checkout -b feature/email-passkey-registration
```

---

### Task 1: Add `OtpScope` enum and refactor `RedisOtpStore` to use scoped string keys

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt`

**Step 1: Write new tests for scoped keys in `RedisOtpStoreTest.kt`**

Replace the entire test file. The key changes: every call now passes `OtpScope` + `String` key. Add a test proving two scopes are independent.

Open `src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt` and replace the full contents with:

```kotlin
package com.aibles.iam.authentication.infra

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.StringRedisTemplate
import org.testcontainers.containers.GenericContainer
import org.testcontainers.junit.jupiter.Container
import org.testcontainers.junit.jupiter.Testcontainers
import java.util.UUID

@Testcontainers
class RedisOtpStoreTest {

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

    private val store: RedisOtpStore by lazy { RedisOtpStore(template) }

    @AfterEach
    fun flush() {
        template.connectionFactory?.connection?.serverCommands()?.flushAll()
    }

    // --- PASSKEY_REG scope (existing behavior, new signature) ---

    @Test
    fun `stores OTP and can retrieve it`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "123456")
        assertThat(store.getOtp(OtpScope.PASSKEY_REG, key)).isEqualTo("123456")
    }

    @Test
    fun `getOtp returns null after deletion`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "999999")
        store.deleteOtp(OtpScope.PASSKEY_REG, key)
        assertThat(store.getOtp(OtpScope.PASSKEY_REG, key)).isNull()
    }

    @Test
    fun `incrementAttempts returns current count`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "111111")
        assertThat(store.incrementAttempts(OtpScope.PASSKEY_REG, key)).isEqualTo(1L)
        assertThat(store.incrementAttempts(OtpScope.PASSKEY_REG, key)).isEqualTo(2L)
    }

    @Test
    fun `saveOtp resets attempt counter`() {
        val key = UUID.randomUUID().toString()
        store.saveOtp(OtpScope.PASSKEY_REG, key, "111111")
        store.incrementAttempts(OtpScope.PASSKEY_REG, key)
        store.incrementAttempts(OtpScope.PASSKEY_REG, key)
        store.saveOtp(OtpScope.PASSKEY_REG, key, "222222")
        assertThat(store.incrementAttempts(OtpScope.PASSKEY_REG, key)).isEqualTo(1L)
    }

    @Test
    fun `saves and consumes otpToken`() {
        val token = UUID.randomUUID().toString()
        store.saveOtpToken(OtpScope.PASSKEY_REG, token, "some-value")
        assertThat(store.consumeOtpToken(OtpScope.PASSKEY_REG, token)).isEqualTo("some-value")
        assertThat(store.consumeOtpToken(OtpScope.PASSKEY_REG, token)).isNull()
    }

    @Test
    fun `incrementSendCount increments on each call`() {
        val key = UUID.randomUUID().toString()
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, key)).isEqualTo(1L)
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, key)).isEqualTo(2L)
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, key)).isEqualTo(3L)
    }

    @Test
    fun `incrementSendCount is independent per key`() {
        val keyA = UUID.randomUUID().toString()
        val keyB = UUID.randomUUID().toString()
        store.incrementSendCount(OtpScope.PASSKEY_REG, keyA)
        store.incrementSendCount(OtpScope.PASSKEY_REG, keyA)
        assertThat(store.incrementSendCount(OtpScope.PASSKEY_REG, keyB)).isEqualTo(1L)
    }

    // --- Cross-scope isolation ---

    @Test
    fun `different scopes are independent`() {
        val key = "shared-key@test.com"
        store.saveOtp(OtpScope.PASSKEY_REG, key, "111111")
        store.saveOtp(OtpScope.SIGNUP, key, "222222")
        assertThat(store.getOtp(OtpScope.PASSKEY_REG, key)).isEqualTo("111111")
        assertThat(store.getOtp(OtpScope.SIGNUP, key)).isEqualTo("222222")
    }

    @Test
    fun `signup scope token stores and consumes string value`() {
        val token = UUID.randomUUID().toString()
        store.saveOtpToken(OtpScope.SIGNUP, token, "user@test.com")
        assertThat(store.consumeOtpToken(OtpScope.SIGNUP, token)).isEqualTo("user@test.com")
        assertThat(store.consumeOtpToken(OtpScope.SIGNUP, token)).isNull()
    }
}
```

**Step 2: Run to confirm tests FAIL (compile error)**

```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisOtpStoreTest"
```
Expected: compilation fails — `OtpScope` not defined, method signatures don't match.

**Step 3: Implement `OtpScope` enum and refactor `RedisOtpStore`**

Create `src/main/kotlin/com/aibles/iam/authentication/infra/OtpScope.kt`:

```kotlin
package com.aibles.iam.authentication.infra

enum class OtpScope(val prefix: String) {
    PASSKEY_REG("otp:reg:"),
    SIGNUP("otp:signup:");
}
```

Replace the full contents of `src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt`:

```kotlin
package com.aibles.iam.authentication.infra

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration

@Component
class RedisOtpStore(private val template: StringRedisTemplate) {

    companion object {
        private val OTP_TTL   = Duration.ofMinutes(5)
        private val TOKEN_TTL = Duration.ofMinutes(10)
        private val SEND_TTL  = Duration.ofMinutes(10)
        const val MAX_ATTEMPTS   = 3L
        const val MAX_SEND_COUNT = 3L
    }

    fun saveOtp(scope: OtpScope, key: String, code: String) {
        template.opsForValue().set("${scope.prefix}$key", code, OTP_TTL)
        template.delete("${scope.prefix}attempts:$key")
    }

    fun getOtp(scope: OtpScope, key: String): String? =
        template.opsForValue().get("${scope.prefix}$key")

    fun deleteOtp(scope: OtpScope, key: String) {
        template.delete(listOf("${scope.prefix}$key", "${scope.prefix}attempts:$key"))
    }

    fun incrementAttempts(scope: OtpScope, key: String): Long {
        val redisKey = "${scope.prefix}attempts:$key"
        val count = template.opsForValue().increment(redisKey) ?: 1L
        if (count == 1L) template.expire(redisKey, OTP_TTL)
        return count
    }

    val maxAttempts: Long get() = MAX_ATTEMPTS

    val maxSendCount: Long get() = MAX_SEND_COUNT

    fun incrementSendCount(scope: OtpScope, key: String): Long {
        val redisKey = "${scope.prefix}sends:$key"
        val count = template.opsForValue().increment(redisKey) ?: 1L
        if (count == 1L) template.expire(redisKey, SEND_TTL)
        return count
    }

    fun saveOtpToken(scope: OtpScope, token: String, value: String) {
        template.opsForValue().set("${scope.prefix}ok:$token", value, TOKEN_TTL)
    }

    fun consumeOtpToken(scope: OtpScope, token: String): String? =
        template.opsForValue().getAndDelete("${scope.prefix}ok:$token")
}
```

**Step 4: Run `RedisOtpStoreTest` to confirm tests PASS**

```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisOtpStoreTest"
```
Expected: `BUILD SUCCESSFUL`, all tests pass.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/infra/OtpScope.kt \
        src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt \
        src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt
git commit -m "refactor(otp): introduce OtpScope enum and generalize RedisOtpStore to scoped string keys"
```

---

### Task 2: Update existing callers to use `OtpScope.PASSKEY_REG`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCaseTest.kt`

**Step 1: Update `SendPasskeyOtpUseCase.kt`**

Add import:
```kotlin
import com.aibles.iam.authentication.infra.OtpScope
```

Replace the execute body (lines 24–39):
```kotlin
    fun execute(command: Command) {
        val user = getUserUseCase.execute(GetUserUseCase.Query(command.userId))

        if (user.email.isBlank()) {
            throw BadRequestException("User has no verified email address.", ErrorCode.BAD_REQUEST)
        }

        val key = command.userId.toString()
        val sends = otpStore.incrementSendCount(OtpScope.PASSKEY_REG, key)
        if (sends > otpStore.maxSendCount) {
            throw BadRequestException("Too many OTP requests. Please try again later.", ErrorCode.OTP_SEND_LIMIT_EXCEEDED)
        }

        val code = String.format("%06d", random.nextInt(1_000_000))
        otpStore.saveOtp(OtpScope.PASSKEY_REG, key, code)
        emailService.sendOtp(user.email, code)
    }
```

**Step 2: Update `VerifyPasskeyOtpUseCase.kt`**

Add import:
```kotlin
import com.aibles.iam.authentication.infra.OtpScope
```

Replace the execute body (lines 15–32):
```kotlin
    fun execute(command: Command): Result {
        val key = command.userId.toString()
        val attempts = otpStore.incrementAttempts(OtpScope.PASSKEY_REG, key)
        if (attempts > otpStore.maxAttempts) {
            throw BadRequestException("Too many OTP attempts. Please request a new code.", ErrorCode.OTP_MAX_ATTEMPTS)
        }

        val stored = otpStore.getOtp(OtpScope.PASSKEY_REG, key)
            ?: throw BadRequestException("OTP expired. Please request a new code.", ErrorCode.OTP_EXPIRED)

        if (stored != command.code) {
            throw BadRequestException("Invalid OTP code.", ErrorCode.OTP_INVALID)
        }

        val otpToken = UUID.randomUUID().toString()
        otpStore.deleteOtp(OtpScope.PASSKEY_REG, key)
        otpStore.saveOtpToken(OtpScope.PASSKEY_REG, otpToken, key)
        return Result(otpToken)
    }
```

**Step 3: Update `RegisterPasskeyStartUseCase.kt`**

Add import:
```kotlin
import com.aibles.iam.authentication.infra.OtpScope
```

Replace lines 44–48 (the otpToken consumption):
```kotlin
        val tokenOwner = otpStore.consumeOtpToken(OtpScope.PASSKEY_REG, command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)
        if (tokenOwner != command.userId.toString()) {
            throw UnauthorizedException("OTP token does not match the authenticated user.", ErrorCode.UNAUTHORIZED)
        }
```

**Step 4: Update `SendPasskeyOtpUseCaseTest.kt`**

Update the mock calls. The `otpStore` is `relaxed = true`, so un-stubbed calls return defaults.

Replace the `saveOtp` stub in the first test (line 32):
```kotlin
        every { otpStore.saveOtp(OtpScope.PASSKEY_REG, userId.toString(), capture(codeSlot)) } returns Unit
```

Replace the send-limit verify lines in the blank-email test (line 52):
```kotlin
        verify(exactly = 0) { otpStore.incrementSendCount(any(), any()) }
```

Replace the send-limit test stubs (lines 61–62):
```kotlin
        every { otpStore.incrementSendCount(OtpScope.PASSKEY_REG, userId.toString()) } returns RedisOtpStore.MAX_SEND_COUNT + 1
        every { otpStore.maxSendCount } returns RedisOtpStore.MAX_SEND_COUNT
```

Replace the send-limit verify lines (lines 69–70):
```kotlin
        verify(exactly = 0) { otpStore.saveOtp(any(), any(), any()) }
```

Add import at top:
```kotlin
import com.aibles.iam.authentication.infra.OtpScope
```

**Step 5: Update `VerifyPasskeyOtpUseCaseTest.kt`**

Add import:
```kotlin
import com.aibles.iam.authentication.infra.OtpScope
```

In `returns otpToken on correct code` test, update stubs:
```kotlin
        every { otpStore.getOtp(OtpScope.PASSKEY_REG, userId.toString()) } returns "123456"
        every { otpStore.incrementAttempts(OtpScope.PASSKEY_REG, userId.toString()) } returns 1L
```
And verifies:
```kotlin
        verify { otpStore.deleteOtp(OtpScope.PASSKEY_REG, userId.toString()) }
        verify { otpStore.saveOtpToken(OtpScope.PASSKEY_REG, result.otpToken, userId.toString()) }
```

In `throws OTP_INVALID` test:
```kotlin
        every { otpStore.getOtp(OtpScope.PASSKEY_REG, userId.toString()) } returns "999999"
        every { otpStore.incrementAttempts(OtpScope.PASSKEY_REG, userId.toString()) } returns 1L
```

In `throws OTP_EXPIRED` test:
```kotlin
        every { otpStore.getOtp(OtpScope.PASSKEY_REG, userId.toString()) } returns null
        every { otpStore.incrementAttempts(OtpScope.PASSKEY_REG, userId.toString()) } returns 1L
```

In `throws OTP_MAX_ATTEMPTS` test:
```kotlin
        every { otpStore.getOtp(OtpScope.PASSKEY_REG, userId.toString()) } returns "123456"
        every { otpStore.incrementAttempts(OtpScope.PASSKEY_REG, userId.toString()) } returns 4L
```

**Step 6: Run all affected tests**

```bash
./gradlew test --tests "com.aibles.iam.authentication.*"
```
Expected: `BUILD SUCCESSFUL`, all existing tests pass with new signatures.

**Step 7: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyPasskeyOtpUseCaseTest.kt
git commit -m "refactor(otp): update existing callers to use OtpScope.PASSKEY_REG with string keys"
```

---

### Task 3: Extract `WebAuthnCeremonyService` from existing passkey use cases

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/infra/WebAuthnCeremonyService.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt`

**Step 1: Create `WebAuthnCeremonyService.kt`**

Create `src/main/kotlin/com/aibles/iam/authentication/infra/WebAuthnCeremonyService.kt`:

```kotlin
package com.aibles.iam.authentication.infra

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
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

@Component
class WebAuthnCeremonyService(
    private val challengeStore: RedisChallengeStore,
    private val webAuthnManager: WebAuthnManager,
    private val props: WebAuthnProperties,
    private val objectConverter: ObjectConverter,
) {
    data class ChallengeData(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>> = listOf(
            mapOf("type" to "public-key", "alg" to -7),
            mapOf("type" to "public-key", "alg" to -257),
        ),
        val timeout: Int = 60_000,
        val attestation: String = "none",
    )

    data class VerifiedCredential(
        val credentialId: ByteArray,
        val publicKeyCose: ByteArray,
        val signCounter: Long,
        val aaguid: UUID?,
    )

    fun createChallenge(): ChallengeData {
        val challengeBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sessionId = UUID.randomUUID().toString()
        challengeStore.storeChallenge(sessionId, challengeBytes)
        return ChallengeData(
            sessionId = sessionId,
            rpId = props.rpId,
            rpName = props.rpName,
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes),
        )
    }

    fun verifyAttestation(sessionId: String, clientDataJSON: String, attestationObject: String): VerifiedCredential {
        val challenge = challengeStore.getAndDeleteChallenge(sessionId)

        val decoder = Base64.getUrlDecoder()
        val clientDataBytes = decoder.decode(clientDataJSON.padBase64Url())
        val attestationBytes = decoder.decode(attestationObject.padBase64Url())

        val registrationRequest = RegistrationRequest(attestationBytes, clientDataBytes)
        val serverProperty = ServerProperty(
            Origin.create(props.rpOrigin),
            props.rpId,
            DefaultChallenge(challenge),
            null,
        )
        val registrationParameters = RegistrationParameters(serverProperty, null, false, true)

        val data = try {
            webAuthnManager.verify(registrationRequest, registrationParameters)
        } catch (e: RuntimeException) {
            throw BadRequestException("Passkey attestation failed: ${e.message}", ErrorCode.PASSKEY_ATTESTATION_FAILED)
        }

        val authData = data.attestationObject!!.authenticatorData
        val credData = authData.attestedCredentialData!!
        val coseKeyBytes = objectConverter.cborConverter.writeValueAsBytes(credData.coseKey)
        val aaguid: UUID? = credData.aaguid.value?.let {
            try { UUID.fromString(it.toString()) } catch (_: Exception) { null }
        }

        return VerifiedCredential(
            credentialId = credData.credentialId,
            publicKeyCose = coseKeyBytes,
            signCounter = authData.signCount,
            aaguid = aaguid,
        )
    }

    private fun String.padBase64Url(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }
}
```

**Step 2: Refactor `RegisterPasskeyStartUseCase.kt` to delegate**

Replace the full contents:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.UnauthorizedException
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class RegisterPasskeyStartUseCase(
    private val otpStore: RedisOtpStore,
    private val ceremonyService: WebAuthnCeremonyService,
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
        val tokenOwner = otpStore.consumeOtpToken(OtpScope.PASSKEY_REG, command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)
        if (tokenOwner != command.userId.toString()) {
            throw UnauthorizedException("OTP token does not match the authenticated user.", ErrorCode.UNAUTHORIZED)
        }

        val challengeData = ceremonyService.createChallenge()
        return Result(
            sessionId = challengeData.sessionId,
            rpId = challengeData.rpId,
            rpName = challengeData.rpName,
            userId = command.userId.toString(),
            userEmail = command.userEmail,
            userDisplayName = command.displayName,
            challenge = challengeData.challenge,
        )
    }
}
```

**Step 3: Refactor `RegisterPasskeyFinishUseCase.kt` to delegate**

Replace the full contents:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class RegisterPasskeyFinishUseCase(
    private val credentialRepository: PasskeyCredentialRepository,
    private val ceremonyService: WebAuthnCeremonyService,
) {

    data class Command(
        val userId: UUID,
        val sessionId: String,
        val clientDataJSON: String,
        val attestationObject: String,
        val displayName: String?,
    )

    fun execute(command: Command) {
        val credential = ceremonyService.verifyAttestation(
            command.sessionId, command.clientDataJSON, command.attestationObject
        )
        credentialRepository.save(
            PasskeyCredential(
                userId = command.userId,
                credentialId = credential.credentialId,
                publicKeyCose = credential.publicKeyCose,
                signCounter = credential.signCounter,
                aaguid = credential.aaguid,
                displayName = command.displayName,
            )
        )
    }
}
```

**Step 4: Run all tests**

```bash
./gradlew test
```
Expected: `BUILD SUCCESSFUL`, all tests pass. The refactored use cases delegate to `WebAuthnCeremonyService`, behavior unchanged.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/infra/WebAuthnCeremonyService.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyStartUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt
git commit -m "refactor(passkey): extract WebAuthnCeremonyService from start/finish use cases"
```

---

### Task 4: Add `EMAIL_ALREADY_REGISTERED` error code + audit events + security config

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`
- Modify: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`

**Step 1: Add error code to `ErrorCode.kt`**

After `OTP_SEND_LIMIT_EXCEEDED` line, add:
```kotlin
    EMAIL_ALREADY_REGISTERED(HttpStatus.CONFLICT),
```

**Step 2: Add audit events to `AuditEvent.kt`**

After `PASSKEY_OTP_VERIFIED`, add:
```kotlin
    REGISTRATION_OTP_SENT,
    REGISTRATION_OTP_VERIFIED,
    REGISTRATION_COMPLETED,
```

**Step 3: Add registration endpoints to `SecurityConfig.kt` permitAll**

In the `requestMatchers` block, after the passkey authenticate lines, add:
```kotlin
                        "/api/v1/auth/register/**",
```

**Step 4: Run full test suite**

```bash
./gradlew test
```
Expected: `BUILD SUCCESSFUL`.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt \
        src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt \
        src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt
git commit -m "feat(register): add EMAIL_ALREADY_REGISTERED error code, audit events, and public endpoint config"
```

---

### Task 5: Create registration use cases (send-otp, verify-otp, start, finish)

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/SendRegistrationOtpUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyRegistrationOtpUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCase.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/SendRegistrationOtpUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyRegistrationOtpUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCaseTest.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCaseTest.kt`

**Step 1: Write failing tests for `SendRegistrationOtpUseCase`**

Create `src/test/kotlin/com/aibles/iam/authentication/usecase/SendRegistrationOtpUseCaseTest.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class SendRegistrationOtpUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val otpStore       = mockk<RedisOtpStore>(relaxed = true)
    private val emailService   = mockk<EmailService>(relaxed = true)
    private val useCase = SendRegistrationOtpUseCase(userRepository, otpStore, emailService)

    @Test
    fun `sends OTP to new email`() {
        every { userRepository.existsByEmail("new@test.com") } returns false

        val codeSlot = slot<String>()
        every { otpStore.saveOtp(OtpScope.SIGNUP, "new@test.com", capture(codeSlot)) } returns Unit

        useCase.execute(SendRegistrationOtpUseCase.Command("new@test.com"))

        assertThat(codeSlot.captured).matches("\\d{6}")
        verify(exactly = 1) { emailService.sendOtp("new@test.com", codeSlot.captured) }
    }

    @Test
    fun `throws EMAIL_ALREADY_REGISTERED when email exists`() {
        every { userRepository.existsByEmail("existing@test.com") } returns true

        assertThatThrownBy { useCase.execute(SendRegistrationOtpUseCase.Command("existing@test.com")) }
            .isInstanceOf(ConflictException::class.java)
            .extracting("errorCode")
            .isEqualTo(ErrorCode.EMAIL_ALREADY_REGISTERED)

        verify(exactly = 0) { otpStore.saveOtp(any(), any(), any()) }
        verify(exactly = 0) { emailService.sendOtp(any(), any()) }
    }

    @Test
    fun `throws OTP_SEND_LIMIT_EXCEEDED when rate limited`() {
        every { userRepository.existsByEmail("new@test.com") } returns false
        every { otpStore.incrementSendCount(OtpScope.SIGNUP, "new@test.com") } returns RedisOtpStore.MAX_SEND_COUNT + 1
        every { otpStore.maxSendCount } returns RedisOtpStore.MAX_SEND_COUNT

        assertThatThrownBy { useCase.execute(SendRegistrationOtpUseCase.Command("new@test.com")) }
            .isInstanceOf(BadRequestException::class.java)
            .extracting("errorCode")
            .isEqualTo(ErrorCode.OTP_SEND_LIMIT_EXCEEDED)

        verify(exactly = 0) { otpStore.saveOtp(any(), any(), any()) }
    }
}
```

**Step 2: Write failing tests for `VerifyRegistrationOtpUseCase`**

Create `src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyRegistrationOtpUseCaseTest.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class VerifyRegistrationOtpUseCaseTest {

    private val otpStore = mockk<RedisOtpStore>(relaxed = true)
    private val useCase  = VerifyRegistrationOtpUseCase(otpStore)

    @Test
    fun `returns otpToken on correct code`() {
        every { otpStore.getOtp(OtpScope.SIGNUP, "user@test.com") } returns "123456"
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val result = useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))

        assertThat(result.otpToken).isNotBlank()
        verify { otpStore.deleteOtp(OtpScope.SIGNUP, "user@test.com") }
        verify { otpStore.saveOtpToken(OtpScope.SIGNUP, result.otpToken, "user@test.com") }
    }

    @Test
    fun `throws OTP_INVALID on wrong code`() {
        every { otpStore.getOtp(OtpScope.SIGNUP, "user@test.com") } returns "999999"
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_INVALID)
    }

    @Test
    fun `throws OTP_EXPIRED when no OTP in store`() {
        every { otpStore.getOtp(OtpScope.SIGNUP, "user@test.com") } returns null
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 1L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }

    @Test
    fun `throws OTP_MAX_ATTEMPTS when attempts exceeded`() {
        every { otpStore.incrementAttempts(OtpScope.SIGNUP, "user@test.com") } returns 4L
        every { otpStore.maxAttempts } returns 3L

        val ex = assertThrows<BadRequestException> {
            useCase.execute(VerifyRegistrationOtpUseCase.Command("user@test.com", "123456"))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_MAX_ATTEMPTS)
    }
}
```

**Step 3: Write failing tests for `StartRegistrationUseCase`**

Create `src/test/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCaseTest.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

class StartRegistrationUseCaseTest {

    private val otpStore = mockk<RedisOtpStore>()
    private val ceremonyService = mockk<WebAuthnCeremonyService>()
    private val useCase = StartRegistrationUseCase(otpStore, ceremonyService)

    @Test
    fun `returns challenge data on valid otpToken`() {
        every { otpStore.consumeOtpToken(OtpScope.SIGNUP, "valid-token") } returns "user@test.com"
        every { ceremonyService.createChallenge() } returns WebAuthnCeremonyService.ChallengeData(
            sessionId = "session-1", rpId = "localhost", rpName = "IAM",
            challenge = "Y2hhbGxlbmdl",
        )

        val result = useCase.execute(StartRegistrationUseCase.Command("valid-token", "My Key"))

        assertThat(result.sessionId).isEqualTo("session-1")
        assertThat(result.email).isEqualTo("user@test.com")
        assertThat(result.challenge).isEqualTo("Y2hhbGxlbmdl")
    }

    @Test
    fun `throws OTP_EXPIRED when otpToken is invalid`() {
        every { otpStore.consumeOtpToken(OtpScope.SIGNUP, "bad-token") } returns null

        val ex = assertThrows<BadRequestException> {
            useCase.execute(StartRegistrationUseCase.Command("bad-token", null))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.OTP_EXPIRED)
    }
}
```

**Step 4: Write failing tests for `FinishRegistrationUseCase`**

Create `src/test/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCaseTest.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.UUID

class FinishRegistrationUseCaseTest {

    private val ceremonyService = mockk<WebAuthnCeremonyService>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val credentialRepository = mockk<PasskeyCredentialRepository>(relaxed = true)
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val challengeStore = mockk<RedisChallengeStore>()
    private val useCase = FinishRegistrationUseCase(
        ceremonyService, createUserUseCase, credentialRepository, issueTokenUseCase, challengeStore
    )

    @Test
    fun `creates user and passkey and issues tokens`() {
        val userId = UUID.randomUUID()
        val user = mockk<User> {
            every { id } returns userId
            every { email } returns "new@test.com"
            every { roles } returns mutableSetOf("USER")
        }
        every { ceremonyService.verifyAttestation("s1", "cdj", "ao") } returns
            WebAuthnCeremonyService.VerifiedCredential(
                credentialId = byteArrayOf(1, 2, 3),
                publicKeyCose = byteArrayOf(4, 5, 6),
                signCounter = 0L,
                aaguid = null,
            )
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(user)
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("jwt", "rt", 900L)

        val result = useCase.execute(
            FinishRegistrationUseCase.Command(
                email = "new@test.com",
                sessionId = "s1",
                clientDataJSON = "cdj",
                attestationObject = "ao",
                displayName = "Key",
            )
        )

        assertThat(result.accessToken).isEqualTo("jwt")
        assertThat(result.refreshToken).isEqualTo("rt")
        verify { credentialRepository.save(any()) }
    }

    @Test
    fun `throws EMAIL_ALREADY_REGISTERED when CreateUserUseCase throws`() {
        every { ceremonyService.verifyAttestation("s1", "cdj", "ao") } returns
            WebAuthnCeremonyService.VerifiedCredential(byteArrayOf(1), byteArrayOf(2), 0L, null)
        every { createUserUseCase.execute(any()) } throws
            ConflictException("Email already registered", ErrorCode.USER_EMAIL_CONFLICT)

        assertThatThrownBy {
            useCase.execute(FinishRegistrationUseCase.Command("dup@test.com", "s1", "cdj", "ao", null))
        }
            .isInstanceOf(ConflictException::class.java)

        verify(exactly = 0) { credentialRepository.save(any()) }
    }
}
```

**Step 5: Run to confirm tests FAIL (compile errors)**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.*Registration*"
```
Expected: compilation fails — use case classes don't exist yet.

**Step 6: Implement all four use cases**

Create `src/main/kotlin/com/aibles/iam/authentication/usecase/SendRegistrationOtpUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.EmailService
import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ConflictException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.security.SecureRandom

@Component
class SendRegistrationOtpUseCase(
    private val userRepository: UserRepository,
    private val otpStore: RedisOtpStore,
    private val emailService: EmailService,
) {
    companion object {
        private val random = SecureRandom()
    }

    data class Command(val email: String)

    fun execute(command: Command) {
        val email = command.email.lowercase().trim()

        if (userRepository.existsByEmail(email)) {
            throw ConflictException("Email already registered.", ErrorCode.EMAIL_ALREADY_REGISTERED)
        }

        val sends = otpStore.incrementSendCount(OtpScope.SIGNUP, email)
        if (sends > otpStore.maxSendCount) {
            throw BadRequestException("Too many OTP requests. Please try again later.", ErrorCode.OTP_SEND_LIMIT_EXCEEDED)
        }

        val code = String.format("%06d", random.nextInt(1_000_000))
        otpStore.saveOtp(OtpScope.SIGNUP, email, code)
        emailService.sendOtp(email, code)
    }
}
```

Create `src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyRegistrationOtpUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class VerifyRegistrationOtpUseCase(private val otpStore: RedisOtpStore) {

    data class Command(val email: String, val code: String)
    data class Result(val otpToken: String)

    fun execute(command: Command): Result {
        val email = command.email.lowercase().trim()
        val attempts = otpStore.incrementAttempts(OtpScope.SIGNUP, email)
        if (attempts > otpStore.maxAttempts) {
            throw BadRequestException("Too many OTP attempts. Please request a new code.", ErrorCode.OTP_MAX_ATTEMPTS)
        }

        val stored = otpStore.getOtp(OtpScope.SIGNUP, email)
            ?: throw BadRequestException("OTP expired. Please request a new code.", ErrorCode.OTP_EXPIRED)

        if (stored != command.code) {
            throw BadRequestException("Invalid OTP code.", ErrorCode.OTP_INVALID)
        }

        val otpToken = UUID.randomUUID().toString()
        otpStore.deleteOtp(OtpScope.SIGNUP, email)
        otpStore.saveOtpToken(OtpScope.SIGNUP, otpToken, email)
        return Result(otpToken)
    }
}
```

Create `src/main/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class StartRegistrationUseCase(
    private val otpStore: RedisOtpStore,
    private val ceremonyService: WebAuthnCeremonyService,
) {
    data class Command(val otpToken: String, val displayName: String?)
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val email: String,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>>,
        val timeout: Int,
        val attestation: String,
    )

    fun execute(command: Command): Result {
        val email = otpStore.consumeOtpToken(OtpScope.SIGNUP, command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)

        val challengeData = ceremonyService.createChallenge()
        return Result(
            sessionId = challengeData.sessionId,
            rpId = challengeData.rpId,
            rpName = challengeData.rpName,
            email = email,
            challenge = challengeData.challenge,
            pubKeyCredParams = challengeData.pubKeyCredParams,
            timeout = challengeData.timeout,
            attestation = challengeData.attestation,
        )
    }
}
```

Create `src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import org.springframework.stereotype.Component

@Component
class FinishRegistrationUseCase(
    private val ceremonyService: WebAuthnCeremonyService,
    private val createUserUseCase: CreateUserUseCase,
    private val credentialRepository: PasskeyCredentialRepository,
    private val issueTokenUseCase: IssueTokenUseCase,
    private val challengeStore: RedisChallengeStore,
) {
    data class Command(
        val email: String,
        val sessionId: String,
        val clientDataJSON: String,
        val attestationObject: String,
        val displayName: String?,
    )
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        // Verify attestation first (before creating user)
        val credential = ceremonyService.verifyAttestation(
            command.sessionId, command.clientDataJSON, command.attestationObject
        )

        // Create user (throws USER_EMAIL_CONFLICT if race condition)
        val userResult = createUserUseCase.execute(
            CreateUserUseCase.Command(email = command.email, displayName = null, googleSub = null)
        )

        // Save passkey credential
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

        // Issue tokens
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(userResult.user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
```

**Step 7: Run all new tests**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.*Registration*"
```
Expected: `BUILD SUCCESSFUL`, all new tests pass.

**Step 8: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/SendRegistrationOtpUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/VerifyRegistrationOtpUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/SendRegistrationOtpUseCaseTest.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/VerifyRegistrationOtpUseCaseTest.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCaseTest.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCaseTest.kt
git commit -m "feat(register): add email+passkey registration use cases with tests"
```

---

### Task 6: Create DTOs + `RegisterController`

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterSendOtpRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterVerifyOtpRequest.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt`

**Step 1: Create DTOs**

Create `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterSendOtpRequest.kt`:

```kotlin
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

data class RegisterSendOtpRequest(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Must be a valid email address")
    val email: String,
)
```

Create `src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterVerifyOtpRequest.kt`:

```kotlin
package com.aibles.iam.authentication.api.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern

data class RegisterVerifyOtpRequest(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Must be a valid email address")
    val email: String,
    @field:Pattern(regexp = "\\d{6}", message = "OTP must be exactly 6 digits")
    val code: String,
)
```

Note: `RegisterStartRequest` already exists with `otpToken` + `displayName` and can be reused for the registration start endpoint.

**Step 2: Create `RegisterController.kt`**

Create `src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt`:

```kotlin
package com.aibles.iam.authentication.api

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.api.dto.RegisterFinishRequest
import com.aibles.iam.authentication.api.dto.RegisterSendOtpRequest
import com.aibles.iam.authentication.api.dto.RegisterStartRequest
import com.aibles.iam.authentication.api.dto.RegisterVerifyOtpRequest
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.api.dto.VerifyOtpResponse
import com.aibles.iam.authentication.usecase.FinishRegistrationUseCase
import com.aibles.iam.authentication.usecase.SendRegistrationOtpUseCase
import com.aibles.iam.authentication.usecase.StartRegistrationUseCase
import com.aibles.iam.authentication.usecase.VerifyRegistrationOtpUseCase
import com.aibles.iam.shared.response.ApiResponse
import jakarta.validation.Valid
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth/register")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Registration", description = "Email + passkey self-registration")
class RegisterController(
    private val sendRegistrationOtpUseCase: SendRegistrationOtpUseCase,
    private val verifyRegistrationOtpUseCase: VerifyRegistrationOtpUseCase,
    private val startRegistrationUseCase: StartRegistrationUseCase,
    private val finishRegistrationUseCase: FinishRegistrationUseCase,
    private val eventPublisher: ApplicationEventPublisher,
) {

    @PostMapping("/send-otp")
    @ResponseStatus(HttpStatus.ACCEPTED)
    fun sendOtp(@Valid @RequestBody request: RegisterSendOtpRequest): ApiResponse<Unit> {
        sendRegistrationOtpUseCase.execute(SendRegistrationOtpUseCase.Command(request.email))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.REGISTRATION_OTP_SENT,
            metadata = mapOf("email" to request.email.lowercase().trim()),
        ))
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/verify-otp")
    fun verifyOtp(@Valid @RequestBody request: RegisterVerifyOtpRequest): ApiResponse<VerifyOtpResponse> {
        val result = verifyRegistrationOtpUseCase.execute(
            VerifyRegistrationOtpUseCase.Command(request.email, request.code)
        )
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.REGISTRATION_OTP_VERIFIED,
            metadata = mapOf("email" to request.email.lowercase().trim()),
        ))
        return ApiResponse.ok(VerifyOtpResponse(result.otpToken))
    }

    @PostMapping("/passkey/start")
    fun passkeyStart(@Valid @RequestBody request: RegisterStartRequest): ApiResponse<StartRegistrationUseCase.Result> {
        val result = startRegistrationUseCase.execute(
            StartRegistrationUseCase.Command(request.otpToken, request.displayName)
        )
        return ApiResponse.ok(result)
    }

    @PostMapping("/passkey/finish")
    fun passkeyFinish(@Valid @RequestBody request: RegisterFinishRequest): ApiResponse<TokenResponse> {
        val result = finishRegistrationUseCase.execute(
            FinishRegistrationUseCase.Command(
                email = request.sessionId, // The email is stored in the challenge store — we need to pass it differently
                sessionId = request.sessionId,
                clientDataJSON = request.clientDataJSON,
                attestationObject = request.attestationObject,
                displayName = request.displayName,
            )
        )
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }
}
```

Wait — the `passkeyFinish` endpoint has a problem: we need the `email` to create the user, but the frontend only sends attestation data. The email was stored when the challenge was created in `passkeyStart`. We need to store it alongside the challenge.

**Step 3: Add email storage to `RedisChallengeStore`**

Open `src/main/kotlin/com/aibles/iam/authentication/infra/RedisChallengeStore.kt` and add methods to store/retrieve the email alongside the challenge:

Replace the full contents of `RedisChallengeStore.kt`:

```kotlin
package com.aibles.iam.authentication.infra

import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.time.Duration
import java.util.Base64

@Component
class RedisChallengeStore(private val template: StringRedisTemplate) {

    companion object {
        private val TTL = Duration.ofMinutes(5)
    }

    fun storeChallenge(sessionId: String, challenge: ByteArray) {
        template.opsForValue().set(
            "wc:$sessionId",
            Base64.getEncoder().encodeToString(challenge),
            TTL,
        )
    }

    fun getAndDeleteChallenge(sessionId: String): ByteArray {
        val encoded = template.opsForValue().getAndDelete("wc:$sessionId")
            ?: throw BadRequestException("WebAuthn challenge expired or not found", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)
        return Base64.getDecoder().decode(encoded)
    }

    /** Store metadata (e.g. email) alongside a session for later retrieval. */
    fun storeSessionData(sessionId: String, key: String, value: String) {
        template.opsForValue().set("wc:$sessionId:$key", value, TTL)
    }

    /** Retrieve and delete session metadata. */
    fun consumeSessionData(sessionId: String, key: String): String? =
        template.opsForValue().getAndDelete("wc:$sessionId:$key")
}
```

**Step 4: Update `StartRegistrationUseCase` to store email in challenge session**

Add `RedisChallengeStore` as a dependency and store email after challenge creation:

Replace the full contents of `src/main/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.infra.OtpScope
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class StartRegistrationUseCase(
    private val otpStore: RedisOtpStore,
    private val ceremonyService: WebAuthnCeremonyService,
    private val challengeStore: RedisChallengeStore,
) {
    data class Command(val otpToken: String, val displayName: String?)
    data class Result(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val email: String,
        val challenge: String,
        val pubKeyCredParams: List<Map<String, Any>>,
        val timeout: Int,
        val attestation: String,
    )

    fun execute(command: Command): Result {
        val email = otpStore.consumeOtpToken(OtpScope.SIGNUP, command.otpToken)
            ?: throw BadRequestException("OTP verification required. Please verify your email first.", ErrorCode.OTP_EXPIRED)

        val challengeData = ceremonyService.createChallenge()

        // Store email alongside challenge session so finish step can retrieve it
        challengeStore.storeSessionData(challengeData.sessionId, "email", email)

        return Result(
            sessionId = challengeData.sessionId,
            rpId = challengeData.rpId,
            rpName = challengeData.rpName,
            email = email,
            challenge = challengeData.challenge,
            pubKeyCredParams = challengeData.pubKeyCredParams,
            timeout = challengeData.timeout,
            attestation = challengeData.attestation,
        )
    }
}
```

**Step 5: Update `FinishRegistrationUseCase` to retrieve email from session**

Replace the full contents of `src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.RedisChallengeStore
import com.aibles.iam.authentication.infra.WebAuthnCeremonyService
import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.springframework.stereotype.Component

@Component
class FinishRegistrationUseCase(
    private val ceremonyService: WebAuthnCeremonyService,
    private val createUserUseCase: CreateUserUseCase,
    private val credentialRepository: PasskeyCredentialRepository,
    private val issueTokenUseCase: IssueTokenUseCase,
    private val challengeStore: RedisChallengeStore,
) {
    data class Command(
        val sessionId: String,
        val clientDataJSON: String,
        val attestationObject: String,
        val displayName: String?,
    )
    data class Result(val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        // Retrieve the email stored during the start step
        val email = challengeStore.consumeSessionData(command.sessionId, "email")
            ?: throw BadRequestException("Registration session expired.", ErrorCode.PASSKEY_CHALLENGE_EXPIRED)

        // Verify attestation (this also consumes the challenge)
        val credential = ceremonyService.verifyAttestation(
            command.sessionId, command.clientDataJSON, command.attestationObject
        )

        // Create user (throws USER_EMAIL_CONFLICT if race condition)
        val userResult = createUserUseCase.execute(
            CreateUserUseCase.Command(email = email, displayName = null, googleSub = null)
        )

        // Save passkey credential
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

        // Issue tokens
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(userResult.user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
```

**Step 6: Fix the controller — `passkeyFinish` no longer needs email in request**

Replace the `passkeyFinish` method in `RegisterController.kt`:

```kotlin
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
        ))
        return ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
    }
```

**Step 7: Update `FinishRegistrationUseCaseTest` for new Command (no email param)**

Update the test to match the new `Command` shape (no `email` field; email comes from `challengeStore`):

In `creates user and passkey and issues tokens`, add:
```kotlin
        every { challengeStore.consumeSessionData("s1", "email") } returns "new@test.com"
```
And update the execute call:
```kotlin
        val result = useCase.execute(
            FinishRegistrationUseCase.Command(
                sessionId = "s1",
                clientDataJSON = "cdj",
                attestationObject = "ao",
                displayName = "Key",
            )
        )
```

In `throws EMAIL_ALREADY_REGISTERED`, add:
```kotlin
        every { challengeStore.consumeSessionData("s1", "email") } returns "dup@test.com"
```
And update the execute call:
```kotlin
        assertThatThrownBy {
            useCase.execute(FinishRegistrationUseCase.Command("s1", "cdj", "ao", null))
        }
```

Also update `StartRegistrationUseCaseTest` to mock `challengeStore`:
Add to class:
```kotlin
    private val challengeStore = mockk<RedisChallengeStore>(relaxed = true)
    private val useCase = StartRegistrationUseCase(otpStore, ceremonyService, challengeStore)
```

**Step 8: Run all tests**

```bash
./gradlew test
```
Expected: `BUILD SUCCESSFUL`, all tests pass.

**Step 9: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/api/RegisterController.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterSendOtpRequest.kt \
        src/main/kotlin/com/aibles/iam/authentication/api/dto/RegisterVerifyOtpRequest.kt \
        src/main/kotlin/com/aibles/iam/authentication/infra/RedisChallengeStore.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCase.kt \
        src/main/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/StartRegistrationUseCaseTest.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/FinishRegistrationUseCaseTest.kt
git commit -m "feat(register): add RegisterController with DTOs, session-based email storage"
```

---

### Task 7: Full test suite verification + PR

**Step 1: Run full test suite**

```bash
./gradlew test
```
Expected: `BUILD SUCCESSFUL`, all tests pass.

**Step 2: Push branch and create PR**

```bash
git push -u origin feature/email-passkey-registration

gh pr create \
  --title "feat(register): email + passkey self-registration flow" \
  --body "$(cat <<'EOF'
## Summary
- Generalize `RedisOtpStore` with `OtpScope` enum for scoped string keys (no more UUID-only)
- Extract `WebAuthnCeremonyService` from existing passkey start/finish use cases (shared infra)
- Add 4 new public endpoints under `/api/v1/auth/register/` for email+passkey registration
- Add `EMAIL_ALREADY_REGISTERED` error code and registration audit events
- Existing passkey registration flow unchanged (uses `OtpScope.PASSKEY_REG`)

## New Endpoints (all public, no JWT)
- `POST /api/v1/auth/register/send-otp` — send OTP to email
- `POST /api/v1/auth/register/verify-otp` — verify OTP, get otpToken
- `POST /api/v1/auth/register/passkey/start` — consume otpToken, get WebAuthn challenge
- `POST /api/v1/auth/register/passkey/finish` — verify attestation, create user + passkey, return tokens

## Test Plan
- [x] `RedisOtpStoreTest` — updated for scoped keys + cross-scope isolation tests
- [x] `SendPasskeyOtpUseCaseTest` — updated for new signature, all pass
- [x] `VerifyPasskeyOtpUseCaseTest` — updated for new signature, all pass
- [x] `SendRegistrationOtpUseCaseTest` — 3 new tests
- [x] `VerifyRegistrationOtpUseCaseTest` — 4 new tests
- [x] `StartRegistrationUseCaseTest` — 2 new tests
- [x] `FinishRegistrationUseCaseTest` — 2 new tests
- [x] Full suite passes

🤖 Generated with [Claude Code](https://claude.ai/claude-code)
EOF
)" \
  --base main
```

**Step 3: Merge and clean up**

```bash
gh pr merge <pr-number> --squash --delete-branch
git checkout main
git pull origin main
```
