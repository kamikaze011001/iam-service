# Auth Flow Bug Fixes — Post Sprint 7 Review

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 10 bugs and security issues found in the post-Sprint-7 code review covering Google OAuth2 and Passkey authentication flows.

**Architecture:** Each fix is a self-contained GitHub issue + feature branch + PR following the per-issue workflow in CLAUDE.md. Tasks 1–6 address critical/important issues; Task 7 batches the three minor issues. Tasks 3 and 4 are independent of each other and of Task 1 — do them in order but note no shared state.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, webauthn4j, Redis (Lettuce), JUnit 5, MockK, Bucket4j

---

## Issues Being Fixed

| Task | Issue # | Severity | Summary |
|------|---------|----------|---------|
| 1 | #1 + #7 | Critical | Zero-counter passkeys (Apple/Windows Hello) always rejected |
| 2 | #2 + #10 | Critical | `googleSub` never linked for email-matched users; orphaned tokens on AS redirect |
| 3 | #5 | Important | Credential counter updated before user-disabled check |
| 4 | #3 | Important | Consumed refresh tokens leak in Redis user-set forever |
| 5 | #4 | Important | Logout only revokes one token; `revokeAllForUser` unreachable from production |
| 6 | #6 | Important | Rate limiter bypassed via forged `X-Forwarded-For` header |
| 7 | #8 + #9 | Minor | Actuator wildcard permit; `ObjectConverter` not injected in RegisterPasskeyFinishUseCase |

---

## Task 1: Fix Zero-Counter Passkey Authentication (Issues #1 + #7)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredential.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialTest.kt`

**Context:** WebAuthn Level 2 spec §6.1 step 21: if BOTH stored signCount and new signCount are `0`, the authenticator does not support counter-based replay detection — this MUST NOT be treated as an error. Apple Passkeys (iCloud Keychain) and Windows Hello both always return `signCount = 0`. The current condition `if (newCounter <= signCounter)` with both at `0` evaluates as `true` and throws `PASSKEY_COUNTER_INVALID`, permanently blocking these users. `webAuthnManager.verify()` already catches the non-zero replay case via `MaliciousCounterValueException`, making the domain check redundant for non-zero counters. The domain check only needs to handle the spec's zero-counter exception.

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "fix(passkey): zero-counter authenticators (Apple Passkeys, Windows Hello) always rejected" \
  --body "## Problem
PasskeyCredential.verifyAndIncrementCounter uses condition \`if (newCounter <= signCounter)\`. When both values are 0 (authenticator doesn't support counters), this throws PASSKEY_COUNTER_INVALID.

WebAuthn Level 2 spec §6.1 step 21 says: if both stored signCount and new signCount are 0, skip the error — the authenticator simply doesn't support counters.

Affected: Apple Passkeys (iCloud Keychain), Windows Hello, many hardware tokens.

## Fix
Change condition to \`if (newCounter != 0L && newCounter <= signCounter)\`.
Also add a zero-counter test case to PasskeyCredentialTest." \
  --label bug
```

Note the issue number printed (e.g. `#87`). Use it in the branch name below.

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-fix-passkey-zero-counter
```

### Step 3: Write failing test first

Open `src/test/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialTest.kt` and add this test **before** the closing brace:

```kotlin
@Test
fun `verifyAndIncrementCounter allows zero counter when stored counter is also zero (spec compliance)`() {
    val c = credential(0)
    c.verifyAndIncrementCounter(0L)   // authenticator doesn't support counters — must not throw
    assertThat(c.signCounter).isEqualTo(0L)
}
```

### Step 4: Run test to confirm it fails

```bash
./gradlew test --tests "com.aibles.iam.authentication.domain.passkey.PasskeyCredentialTest.verifyAndIncrementCounter allows zero counter when stored counter is also zero (spec compliance)"
```

Expected: **FAIL** — `UnauthorizedException: Counter replay detected`

### Step 5: Fix the domain method

In `src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredential.kt`, change:

```kotlin
// BEFORE
fun verifyAndIncrementCounter(newCounter: Long) {
    if (newCounter <= signCounter)
        throw UnauthorizedException("Counter replay detected", ErrorCode.PASSKEY_COUNTER_INVALID)
    signCounter = newCounter
}
```

to:

```kotlin
// AFTER
fun verifyAndIncrementCounter(newCounter: Long) {
    // WebAuthn spec §6.1 step 21: if both counters are 0 the authenticator does not support
    // counter-based replay detection — this is NOT an error. Apple Passkeys and Windows Hello
    // both use signCount = 0 permanently.
    if (newCounter != 0L && newCounter <= signCounter)
        throw UnauthorizedException("Counter replay detected", ErrorCode.PASSKEY_COUNTER_INVALID)
    signCounter = newCounter
}
```

### Step 6: Run the full test class to verify no regressions

```bash
./gradlew test --tests "com.aibles.iam.authentication.domain.passkey.PasskeyCredentialTest"
```

Expected: **4 tests PASS** (3 existing + 1 new)

### Step 7: Run full test suite

```bash
./gradlew test
```

Expected: all tests pass.

### Step 8: Commit and push

```bash
git add src/main/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredential.kt \
        src/test/kotlin/com/aibles/iam/authentication/domain/passkey/PasskeyCredentialTest.kt
git commit -m "fix(passkey): allow zero-counter authenticators per WebAuthn spec §6.1 step 21 (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-fix-passkey-zero-counter
```

### Step 9: Create PR and merge

```bash
gh pr create \
  --title "fix(passkey): allow zero-counter authenticators per WebAuthn spec" \
  --body "Closes #<issue-number>

Changes:
- PasskeyCredential.verifyAndIncrementCounter: skip replay check when both stored and new counters are 0 (spec §6.1 step 21)
- Adds test: zero-counter authenticator must not throw

Affects: Apple Passkeys (iCloud Keychain), Windows Hello, hardware tokens without counter support."
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 2: Fix Google Account Linking + Eliminate Orphaned Tokens on AS Redirect (Issues #2 + #10)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/identity/domain/user/User.kt`
- Create: `src/main/kotlin/com/aibles/iam/authentication/usecase/SyncGoogleUserUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCase.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`
- Create: `src/test/kotlin/com/aibles/iam/authentication/usecase/SyncGoogleUserUseCaseTest.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCaseTest.kt`

**Context (Issue #2):** `User.googleSub` is a `val` (immutable). When `LoginWithGoogleUseCase` finds a user by email fallback (pre-created account), it never writes the `googleSub` back. Every subsequent Google login re-hits `findByEmail`. Worse: `OidcTokenCustomizer.customize()` does `userRepository.findByGoogleSub(googleSub) ?: return` — since `googleSub` is still null in the DB, the `return` fires silently and the AS-issued ID token is emitted without `email`, `name`, or `roles` claims.

**Context (Issue #10):** `GoogleOAuth2SuccessHandler` calls `loginWithGoogleUseCase.execute()` (which issues JWT + refresh token) unconditionally, THEN checks if this is an AS redirect. For AS flows, the issued tokens are immediately discarded, creating orphaned refresh tokens in Redis that stay for 30 days.

**Fix strategy:** Extract a `SyncGoogleUserUseCase` (upsert user + link googleSub + recordLogin, no token issuance). `LoginWithGoogleUseCase` delegates to it. `GoogleOAuth2SuccessHandler` checks for AS redirect FIRST; for AS path, calls `SyncGoogleUserUseCase`; for direct path, calls `LoginWithGoogleUseCase`.

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "fix(auth): googleSub never persisted for email-matched users; orphaned tokens on AS redirect" \
  --body "## Problem 1 — Issue #2
LoginWithGoogleUseCase finds pre-created user by email but User.googleSub is val (immutable) and never written. OidcTokenCustomizer.findByGoogleSub() returns null for these users → ID tokens silently missing email/name/roles claims.

## Problem 2 — Issue #10
GoogleOAuth2SuccessHandler calls loginWithGoogleUseCase.execute() (which issues JWT + refresh token) before checking if this is an AS redirect. For AS flows the tokens are discarded, creating orphaned Redis entries.

## Fix
1. Change User.googleSub from val to var, add User.linkGoogleAccount(sub)
2. Extract SyncGoogleUserUseCase (upsert + link + recordLogin, no tokens)
3. LoginWithGoogleUseCase delegates to SyncGoogleUserUseCase + adds token issuance
4. GoogleOAuth2SuccessHandler checks savedRequest FIRST; AS path uses SyncGoogleUserUseCase; direct path uses LoginWithGoogleUseCase" \
  --label bug
```

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-fix-google-sub-linking
```

### Step 3: Make `googleSub` mutable and add `linkGoogleAccount` method

In `src/main/kotlin/com/aibles/iam/identity/domain/user/User.kt`, change:

```kotlin
// BEFORE (line 22)
@Column(unique = true) val googleSub: String? = null,
```

to:

```kotlin
// AFTER
@Column(unique = true) var googleSub: String? = null,
```

Also add this method inside the `User` class body (after `recordLogin()`):

```kotlin
fun linkGoogleAccount(googleSub: String) {
    this.googleSub = googleSub
    updatedAt = Instant.now()
}
```

### Step 4: Write failing test for `SyncGoogleUserUseCase` (email-path links googleSub)

Create `src/test/kotlin/com/aibles/iam/authentication/usecase/SyncGoogleUserUseCaseTest.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.core.oidc.OidcUserInfo
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority
import java.time.Instant

class SyncGoogleUserUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val createUserUseCase = mockk<CreateUserUseCase>()
    private val useCase = SyncGoogleUserUseCase(userRepository, createUserUseCase)

    private fun oidcUser(sub: String, email: String, name: String? = "Test User"): DefaultOidcUser {
        val claims = mutableMapOf<String, Any>("sub" to sub, "iss" to "https://accounts.google.com")
        val idToken = OidcIdToken("token-value", Instant.now(), Instant.now().plusSeconds(3600), claims)
        val userInfoClaims = mutableMapOf<String, Any>("sub" to sub, "email" to email)
        if (name != null) userInfoClaims["name"] = name
        val userInfo = OidcUserInfo(userInfoClaims)
        return DefaultOidcUser(listOf(OidcUserAuthority(idToken, userInfo)), idToken, userInfo, "sub")
    }

    @Test
    fun `new user is created when neither googleSub nor email match`() {
        val oidcUser = oidcUser("sub-new", "new@example.com")
        val newUser = User.create("new@example.com", "Test User", "sub-new")
        every { userRepository.findByGoogleSub("sub-new") } returns null
        every { userRepository.findByEmail("new@example.com") } returns null
        every { createUserUseCase.execute(any()) } returns CreateUserUseCase.Result(newUser)
        every { userRepository.save(newUser) } returns newUser

        val result = useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))

        assertThat(result.user.email).isEqualTo("new@example.com")
        verify(exactly = 1) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `email-matched user gets googleSub linked and saved`() {
        val oidcUser = oidcUser("sub-link", "preexisting@example.com")
        val existingUser = User.create("preexisting@example.com", "Pre User")   // googleSub is null
        assertThat(existingUser.googleSub).isNull()

        every { userRepository.findByGoogleSub("sub-link") } returns null
        every { userRepository.findByEmail("preexisting@example.com") } returns existingUser
        val savedSlot = slot<User>()
        every { userRepository.save(capture(savedSlot)) } returns existingUser

        useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))

        assertThat(savedSlot.captured.googleSub).isEqualTo("sub-link")
        verify(exactly = 0) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `existing user found by googleSub is returned without creating`() {
        val existingUser = User.create("existing@example.com", "Alice", "sub-existing")
        val oidcUser = oidcUser("sub-existing", "existing@example.com")
        every { userRepository.findByGoogleSub("sub-existing") } returns existingUser
        every { userRepository.save(existingUser) } returns existingUser

        val result = useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))

        assertThat(result.user.email).isEqualTo("existing@example.com")
        verify(exactly = 0) { createUserUseCase.execute(any()) }
    }

    @Test
    fun `disabled user throws ForbiddenException`() {
        val disabledUser = User.create("disabled@example.com").also { it.disable() }
        val oidcUser = oidcUser("sub-d", "disabled@example.com")
        every { userRepository.findByGoogleSub("sub-d") } returns disabledUser
        every { userRepository.save(disabledUser) } returns disabledUser

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(SyncGoogleUserUseCase.Command(oidcUser))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
    }
}
```

### Step 5: Run test to confirm it fails (class not found)

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.SyncGoogleUserUseCaseTest"
```

Expected: **FAIL** — compilation error, `SyncGoogleUserUseCase` not found.

### Step 6: Create `SyncGoogleUserUseCase`

Create `src/main/kotlin/com/aibles/iam/authentication/usecase/SyncGoogleUserUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component

@Component
class SyncGoogleUserUseCase(
    private val userRepository: UserRepository,
    private val createUserUseCase: CreateUserUseCase,
) {
    data class Command(val oidcUser: OidcUser)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        val googleSub = command.oidcUser.subject
        val email = command.oidcUser.email ?: error("Google OIDC user missing email")
        val name = command.oidcUser.fullName

        val user = userRepository.findByGoogleSub(googleSub)
            ?: userRepository.findByEmail(email)?.also { it.linkGoogleAccount(googleSub) }
            ?: createUserUseCase.execute(CreateUserUseCase.Command(email, name, googleSub)).user

        if (!user.isActive())
            throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        user.recordLogin()
        userRepository.save(user)
        return Result(user)
    }
}
```

### Step 7: Run `SyncGoogleUserUseCaseTest` — all 4 must pass

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.SyncGoogleUserUseCaseTest"
```

Expected: **4 tests PASS**

### Step 8: Refactor `LoginWithGoogleUseCase` to delegate to `SyncGoogleUserUseCase`

Replace the entire content of `src/main/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCase.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.stereotype.Component

@Component
class LoginWithGoogleUseCase(
    private val syncGoogleUserUseCase: SyncGoogleUserUseCase,
    private val issueTokenUseCase: IssueTokenUseCase,
) {
    data class Command(val oidcUser: OidcUser)
    data class Result(val user: User, val accessToken: String, val refreshToken: String, val expiresIn: Long)

    fun execute(command: Command): Result {
        val user = syncGoogleUserUseCase.execute(SyncGoogleUserUseCase.Command(command.oidcUser)).user
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(user, tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
    }
}
```

### Step 9: Update `LoginWithGoogleUseCaseTest` to reflect new delegates

Replace the entire content of `src/test/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCaseTest.kt`:

```kotlin
package com.aibles.iam.authentication.usecase

import com.aibles.iam.authorization.usecase.IssueTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.ForbiddenException
import io.mockk.every
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

class LoginWithGoogleUseCaseTest {

    private val syncGoogleUserUseCase = mockk<SyncGoogleUserUseCase>()
    private val issueTokenUseCase = mockk<IssueTokenUseCase>()
    private val useCase = LoginWithGoogleUseCase(syncGoogleUserUseCase, issueTokenUseCase)

    private fun oidcUser(sub: String, email: String): DefaultOidcUser {
        val claims = mutableMapOf<String, Any>("sub" to sub, "iss" to "https://accounts.google.com")
        val idToken = OidcIdToken("token-value", Instant.now(), Instant.now().plusSeconds(3600), claims)
        val userInfoClaims = mutableMapOf<String, Any>("sub" to sub, "email" to email)
        val userInfo = OidcUserInfo(userInfoClaims)
        return DefaultOidcUser(listOf(OidcUserAuthority(idToken, userInfo)), idToken, userInfo, "sub")
    }

    @Test
    fun `delegates to syncGoogleUserUseCase and issues tokens`() {
        val user = User.create("test@example.com", "Test", "sub-1")
        val oidcUser = oidcUser("sub-1", "test@example.com")
        every { syncGoogleUserUseCase.execute(any()) } returns SyncGoogleUserUseCase.Result(user)
        every { issueTokenUseCase.execute(any()) } returns IssueTokenUseCase.Result("access", "refresh", 900)

        val result = useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))

        assertThat(result.accessToken).isEqualTo("access")
        assertThat(result.refreshToken).isEqualTo("refresh")
        assertThat(result.user).isEqualTo(user)
        verify(exactly = 1) { syncGoogleUserUseCase.execute(any()) }
        verify(exactly = 1) { issueTokenUseCase.execute(any()) }
    }

    @Test
    fun `propagates ForbiddenException from syncGoogleUserUseCase`() {
        val oidcUser = oidcUser("sub-d", "disabled@example.com")
        every { syncGoogleUserUseCase.execute(any()) } throws
            ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        val ex = assertThrows<ForbiddenException> {
            useCase.execute(LoginWithGoogleUseCase.Command(oidcUser))
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_DISABLED)
        verify(exactly = 0) { issueTokenUseCase.execute(any()) }
    }
}
```

### Step 10: Fix `GoogleOAuth2SuccessHandler` to check AS redirect first

Replace the entire content of `src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt`:

```kotlin
package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.authentication.usecase.SyncGoogleUserUseCase
import com.aibles.iam.shared.response.ApiResponse
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
    private val requestCache: HttpSessionRequestCache = HttpSessionRequestCache(),
    private val savedRequestHandler: SavedRequestAwareAuthenticationSuccessHandler = SavedRequestAwareAuthenticationSuccessHandler(),
) : AuthenticationSuccessHandler {

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

        // Check for OAuth2 AS authorization code flow FIRST to avoid issuing tokens that
        // will be immediately discarded. The AS redirect path only needs the user to exist
        // in the DB — token issuance is handled by the AS after redirecting back.
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

        // Direct Google login flow: upsert user + issue tokens + return JSON.
        // Note: first-time users also trigger USER_CREATED (from CreateUserUseCase), so
        // a first login produces two audit events: USER_CREATED + LOGIN_GOOGLE_SUCCESS.
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
            userId = result.user.id,
            actorId = result.user.id,
            metadata = mapOf("email" to result.user.email),
        ))
        val body = ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpServletResponse.SC_OK
        objectMapper.writeValue(response.writer, body)
    }
}
```

### Step 11: Run all authentication tests

```bash
./gradlew test --tests "com.aibles.iam.authentication.*"
```

Expected: all pass.

### Step 12: Run full test suite

```bash
./gradlew test
```

Expected: all pass.

### Step 13: Commit and push

```bash
git add \
  src/main/kotlin/com/aibles/iam/identity/domain/user/User.kt \
  src/main/kotlin/com/aibles/iam/authentication/usecase/SyncGoogleUserUseCase.kt \
  src/main/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCase.kt \
  src/main/kotlin/com/aibles/iam/authentication/infra/GoogleOAuth2SuccessHandler.kt \
  src/test/kotlin/com/aibles/iam/authentication/usecase/SyncGoogleUserUseCaseTest.kt \
  src/test/kotlin/com/aibles/iam/authentication/usecase/LoginWithGoogleUseCaseTest.kt
git commit -m "fix(auth): link googleSub for email-matched users; avoid orphaned tokens on AS redirect (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-fix-google-sub-linking
```

### Step 14: Create PR and merge

```bash
gh pr create \
  --title "fix(auth): link googleSub for email-matched users; avoid orphaned tokens on AS redirect" \
  --body "Closes #<issue-number>

Changes:
- User.googleSub: val → var, add linkGoogleAccount(sub) domain method
- New SyncGoogleUserUseCase: upsert user + link googleSub + recordLogin (no token issuance)
- LoginWithGoogleUseCase: delegates to SyncGoogleUserUseCase + adds token issuance
- GoogleOAuth2SuccessHandler: checks savedRequest FIRST; AS path uses SyncGoogleUserUseCase (no wasted tokens); direct path uses LoginWithGoogleUseCase
- OidcTokenCustomizer now works correctly for pre-provisioned users (googleSub persisted)"
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 3: Fix Credential Counter Persisted Before User-Disabled Check (Issue #5)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCaseTest.kt`

**Context:** Steps 6 (counter update + `credentialRepository.save`) happen before Step 7 (user status check). A disabled user's credential gets its counter permanently advanced and `lastUsedAt` updated on every rejected authentication attempt. Correct ordering: load user first, check disabled, THEN update credential.

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "fix(passkey): credential counter updated before user-disabled check in authenticate finish" \
  --body "AuthenticatePasskeyFinishUseCase persists credential counter/lastUsedAt before checking if the user account is active. Disabled users' credentials are modified on every failed auth attempt. Fix: load user and check status before saving the credential." \
  --label bug
```

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-fix-passkey-auth-order
```

### Step 3: Write failing test

In `src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCaseTest.kt`, add this test after the last `@Test`:

```kotlin
@Test
fun `disabled user throws ForbiddenException without saving credential`() {
    val mockAuthData = mockk<AuthenticationData>(relaxed = true)
    every { mockAuthData.authenticatorData!!.signCount } returns 6L

    every { credentialRepository.findByCredentialId(any()) } returns storedCredential
    every { redisChallengeStore.getAndDeleteChallenge("sess") } returns ByteArray(32)
    every { webAuthnManager.verify(any<AuthenticationRequest>(), any<AuthenticationParameters>()) } returns mockAuthData
    // getUserUseCase returns a disabled user
    val disabledUser = User.create("disabled@test.com").also { it.disable() }
    every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns disabledUser

    assertThrows<com.aibles.iam.shared.error.ForbiddenException> { useCase.execute(command()) }

    // Credential must NOT have been saved
    verify(exactly = 0) { credentialRepository.save(any()) }
}
```

Add the missing import to the test file:
```kotlin
import io.mockk.verify
```

### Step 4: Run test to confirm it fails

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCaseTest.disabled user throws ForbiddenException without saving credential"
```

Expected: **FAIL** — test will fail because `credentialRepository.save` IS called in current code before the user check.

### Step 5: Fix the ordering in `AuthenticatePasskeyFinishUseCase`

In `src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt`, reorder Steps 6 and 7. Replace the block from `// Step 6` to `return Result(...)`:

```kotlin
        // Step 6: load user and verify account is active BEFORE modifying any credential state
        val user = getUserUseCase.execute(GetUserUseCase.Query(credential.userId))
        if (!user.isActive()) throw ForbiddenException("Account is disabled", ErrorCode.USER_DISABLED)

        // Step 7: update counter and last-used timestamp now that user is confirmed active
        credential.verifyAndIncrementCounter(authData.authenticatorData!!.signCount)
        credential.lastUsedAt = Instant.now()
        credentialRepository.save(credential)

        // Step 8: issue tokens
        val tokens = issueTokenUseCase.execute(IssueTokenUseCase.Command(user))
        return Result(tokens.accessToken, tokens.refreshToken, tokens.expiresIn)
```

Also remove the now-deleted old Step 7 block (original lines 112–115).

### Step 6: Run all passkey auth tests

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCaseTest"
```

Expected: **5 tests PASS** (4 existing + 1 new)

### Step 7: Run full test suite

```bash
./gradlew test
```

### Step 8: Commit, push, PR, merge

```bash
git add \
  src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt \
  src/test/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCaseTest.kt
git commit -m "fix(passkey): check user status before persisting credential counter (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-fix-passkey-auth-order
gh pr create --title "fix(passkey): check user status before persisting credential counter" --body "Closes #<issue-number>"
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 4: Fix Refresh Token User-Set Memory Leak (Issue #3)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authorization/infra/RedisTokenStore.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authorization/infra/RedisTokenStoreTest.kt`

**Context:** `validateAndConsume` deletes `rt:$token` atomically but never removes the token string from the user's set `rt:u:{userId}`. On every token rotation, the dead token string accumulates in the set forever (until `revokeAllForUser` is called on logout). For users who never log out (e.g., mobile apps), this set grows unboundedly.

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "fix(token): consumed refresh tokens never removed from Redis user-set causing memory leak" \
  --body "RedisTokenStore.validateAndConsume deletes rt:\$token but not the entry in rt:u:\$userId. Each token rotation leaves a dead entry. Fix: after getAndDelete, remove the token from the user set." \
  --label bug
```

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-fix-token-set-cleanup
```

### Step 3: Write failing test

In `src/test/kotlin/com/aibles/iam/authorization/infra/RedisTokenStoreTest.kt`, add after the last `@Test`:

```kotlin
@Test
fun `consumed token is removed from user set`() {
    val userId = UUID.randomUUID()
    val t1 = UUID.randomUUID().toString()
    val t2 = UUID.randomUUID().toString()
    store.storeRefreshToken(t1, userId, Duration.ofMinutes(30))
    store.storeRefreshToken(t2, userId, Duration.ofMinutes(30))

    store.validateAndConsume(t1)  // consume t1

    // t1 must no longer be in the user set
    val members = template.opsForSet().members("rt:u:$userId") ?: emptySet<String>()
    assertThat(members).doesNotContain(t1)
    assertThat(members).contains(t2)   // t2 still active
}
```

### Step 4: Run test to confirm it fails

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.RedisTokenStoreTest.consumed token is removed from user set"
```

Expected: **FAIL** — the user set still contains `t1` after consume.

### Step 5: Fix `validateAndConsume` in `RedisTokenStore`

In `src/main/kotlin/com/aibles/iam/authorization/infra/RedisTokenStore.kt`, replace `validateAndConsume`:

```kotlin
override fun validateAndConsume(token: String): UUID {
    val userId = template.opsForValue().getAndDelete("rt:$token")
        ?: throw UnauthorizedException("Refresh token invalid or expired", ErrorCode.TOKEN_INVALID)
    val userUUID = UUID.fromString(userId)
    template.opsForSet().remove("rt:u:$userUUID", token)
    return userUUID
}
```

### Step 6: Run full `RedisTokenStoreTest`

```bash
./gradlew test --tests "com.aibles.iam.authorization.infra.RedisTokenStoreTest"
```

Expected: **5 tests PASS** (4 existing + 1 new)

### Step 7: Run full test suite

```bash
./gradlew test
```

### Step 8: Commit, push, PR, merge

```bash
git add \
  src/main/kotlin/com/aibles/iam/authorization/infra/RedisTokenStore.kt \
  src/test/kotlin/com/aibles/iam/authorization/infra/RedisTokenStoreTest.kt
git commit -m "fix(token): remove consumed refresh token from Redis user-set to prevent memory leak (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-fix-token-set-cleanup
gh pr create --title "fix(token): remove consumed refresh token from Redis user-set" --body "Closes #<issue-number>"
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 5: Fix Logout to Revoke All Sessions (Issue #4)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCaseTest.kt`

**Context:** `RevokeTokenUseCase` calls `tokenStore.validateAndConsume(token)` which only revokes the one submitted token. A user logged in on 3 devices: logout on one leaves two sessions live. `tokenStore.revokeAllForUser(userId)` was never called from production code. Logout should terminate all sessions for security — once the user explicitly logs out, all concurrent sessions are invalidated (prevents stolen token abuse).

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "fix(token): logout only revokes submitted token instead of all user sessions" \
  --body "RevokeTokenUseCase calls validateAndConsume (single token). revokeAllForUser is unreachable from any production code path. Logout should revoke all sessions for the user to prevent stolen token abuse." \
  --label bug
```

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-fix-logout-revoke-all
```

### Step 3: Read the existing `RevokeTokenUseCaseTest`

Before writing tests, read:
```
src/test/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCaseTest.kt
```

### Step 4: Write failing test

In `RevokeTokenUseCaseTest.kt`, add a test that verifies `revokeAllForUser` is called:

```kotlin
@Test
fun `logout revokes all sessions for the user`() {
    val userId = UUID.randomUUID()
    every { tokenStore.validateAndConsume("token-1") } returns userId
    every { tokenStore.revokeAllForUser(userId) } returns Unit   // or justRun { ... }
    every { eventPublisher.publishEvent(any<Any>()) } returns Unit

    useCase.execute(RevokeTokenUseCase.Command("token-1"))

    verify(exactly = 1) { tokenStore.revokeAllForUser(userId) }
}
```

(Adjust mock setup to match the existing test pattern in the file.)

### Step 5: Run test to confirm it fails

```bash
./gradlew test --tests "com.aibles.iam.authorization.usecase.RevokeTokenUseCaseTest.logout revokes all sessions for the user"
```

Expected: **FAIL** — `revokeAllForUser` is never called.

### Step 6: Fix `RevokeTokenUseCase`

In `src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt`, replace the `execute` body:

```kotlin
fun execute(command: Command) {
    try {
        val userId = tokenStore.validateAndConsume(command.refreshToken)
        tokenStore.revokeAllForUser(userId)   // revoke all remaining sessions for this user
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.TOKEN_REVOKED,
            userId = userId,
            actorId = userId,
        ))
    } catch (e: UnauthorizedException) {
        // already revoked/expired — logout is idempotent
    }
}
```

### Step 7: Run full test suite

```bash
./gradlew test
```

### Step 8: Commit, push, PR, merge

```bash
git add \
  src/main/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCase.kt \
  src/test/kotlin/com/aibles/iam/authorization/usecase/RevokeTokenUseCaseTest.kt
git commit -m "fix(token): revoke all user sessions on logout, not just the submitted token (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-fix-logout-revoke-all
gh pr create --title "fix(token): revoke all user sessions on logout" --body "Closes #<issue-number>"
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 6: Fix Rate Limiter IP Spoofing via X-Forwarded-For (Issue #6)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/RateLimitProperties.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilter.kt`
- Modify: `src/main/resources/application.yml`
- Modify: `src/test/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilterTest.kt`

**Context:** `resolveClientIp` unconditionally trusts `X-Forwarded-For`. Any attacker can send `X-Forwarded-For: 1.2.3.4` to bypass per-IP rate limiting. Fix: only trust `X-Forwarded-For` if the direct connecting IP (`remoteAddr`) is on an explicit trusted-proxies list. By default the list is empty (no proxy trust). Deployments behind a reverse proxy configure the proxy's IP in `rate-limit.trusted-proxies`.

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "fix(security): rate limiter bypassed via forged X-Forwarded-For header" \
  --body "RateLimitFilter.resolveClientIp trusts X-Forwarded-For unconditionally. Any request can include a fake IP to bypass per-IP rate limiting. Fix: only trust X-Forwarded-For when remoteAddr is in a configured trusted-proxies list (empty by default)." \
  --label "security,bug"
```

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-fix-rate-limit-xff-spoofing
```

### Step 3: Write failing test

In `src/test/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilterTest.kt`, add:

```kotlin
@Test
fun `X-Forwarded-For is ignored when remoteAddr is not a trusted proxy`() {
    // Limit = 1 request. If XFF were trusted, "spoofed-ip" would get its own bucket.
    // Since remoteAddr "127.0.0.1" is not in trusted proxies, XFF is ignored and
    // both requests share the same bucket (keyed on "127.0.0.1"), so the 2nd is rejected.
    val props = RateLimitProperties(enabled = true, requestsPerMinute = 1, trustedProxies = emptyList())
    val filter = RateLimitFilter(props, objectMapper)
    val chain = FilterChain { _, _ -> }

    val req1 = MockHttpServletRequest().apply {
        remoteAddr = "127.0.0.1"
        addHeader("X-Forwarded-For", "spoofed-ip")
    }
    filter.doFilter(req1, MockHttpServletResponse(), chain)

    val req2 = MockHttpServletRequest().apply {
        remoteAddr = "127.0.0.1"
        addHeader("X-Forwarded-For", "spoofed-ip")
    }
    val resp2 = MockHttpServletResponse()
    filter.doFilter(req2, resp2, chain)

    assertThat(resp2.status).isEqualTo(429)
}

@Test
fun `X-Forwarded-For is used when remoteAddr is a trusted proxy`() {
    val props = RateLimitProperties(enabled = true, requestsPerMinute = 1, trustedProxies = listOf("10.0.0.1"))
    val filter = RateLimitFilter(props, objectMapper)
    val chain = FilterChain { _, _ -> }

    // Request from trusted proxy 10.0.0.1 with client IP 1.2.3.4
    val req1 = MockHttpServletRequest().apply {
        remoteAddr = "10.0.0.1"
        addHeader("X-Forwarded-For", "1.2.3.4")
    }
    filter.doFilter(req1, MockHttpServletResponse(), chain)

    // Different client IP 5.6.7.8 from same proxy — gets its own bucket, not throttled
    val req2 = MockHttpServletRequest().apply {
        remoteAddr = "10.0.0.1"
        addHeader("X-Forwarded-For", "5.6.7.8")
    }
    val resp2 = MockHttpServletResponse()
    filter.doFilter(req2, resp2, chain)

    assertThat(resp2.status).isNotEqualTo(429)
}
```

Also update the existing `uses X-Forwarded-For header when present` test to include `trustedProxies`:

```kotlin
@Test
fun `uses X-Forwarded-For header when present`() {
    // The test's MockHttpServletRequest has remoteAddr "127.0.0.1" by default
    val props = RateLimitProperties(enabled = true, requestsPerMinute = 1, trustedProxies = listOf("127.0.0.1"))
    val filter = RateLimitFilter(props, objectMapper)
    val chain = FilterChain { _, _ -> }

    val req1 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "1.2.3.4") }
    filter.doFilter(req1, MockHttpServletResponse(), chain)

    val req2 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "5.6.7.8") }
    val resp2 = MockHttpServletResponse()
    filter.doFilter(req2, resp2, chain)
    assertThat(resp2.status).isNotEqualTo(429)

    val req3 = MockHttpServletRequest().apply { addHeader("X-Forwarded-For", "1.2.3.4") }
    val resp3 = MockHttpServletResponse()
    filter.doFilter(req3, resp3, chain)
    assertThat(resp3.status).isEqualTo(429)
}
```

### Step 4: Run tests to confirm they fail

```bash
./gradlew test --tests "com.aibles.iam.shared.ratelimit.RateLimitFilterTest"
```

Expected: the new tests fail (compile error or logic mismatch with existing `RateLimitProperties`).

### Step 5: Add `trustedProxies` to `RateLimitProperties`

In `src/main/kotlin/com/aibles/iam/shared/config/RateLimitProperties.kt`, replace:

```kotlin
@ConfigurationProperties(prefix = "rate-limit")
data class RateLimitProperties(
    val enabled: Boolean = true,
    val requestsPerMinute: Long = 100,
    val trustedProxies: List<String> = emptyList(),
)
```

### Step 6: Fix `resolveClientIp` in `RateLimitFilter`

In `src/main/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilter.kt`, replace `resolveClientIp`:

```kotlin
private fun resolveClientIp(request: HttpServletRequest): String {
    val remoteAddr = request.remoteAddr
    if (properties.trustedProxies.contains(remoteAddr)) {
        val xff = request.getHeader("X-Forwarded-For")
        if (!xff.isNullOrBlank()) {
            return xff.split(",").first().trim()
        }
    }
    return remoteAddr
}
```

### Step 7: Update `application.yml`

In `src/main/resources/application.yml`, update the `rate-limit` block:

```yaml
rate-limit:
  enabled: ${RATE_LIMIT_ENABLED:true}
  requests-per-minute: ${RATE_LIMIT_RPM:100}
  trusted-proxies: ${RATE_LIMIT_TRUSTED_PROXIES:}
```

### Step 8: Run full `RateLimitFilterTest`

```bash
./gradlew test --tests "com.aibles.iam.shared.ratelimit.RateLimitFilterTest"
```

Expected: **6 tests PASS** (4 existing + 2 new)

### Step 9: Run full test suite

```bash
./gradlew test
```

### Step 10: Commit, push, PR, merge

```bash
git add \
  src/main/kotlin/com/aibles/iam/shared/config/RateLimitProperties.kt \
  src/main/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilter.kt \
  src/main/resources/application.yml \
  src/test/kotlin/com/aibles/iam/shared/ratelimit/RateLimitFilterTest.kt
git commit -m "fix(security): only trust X-Forwarded-For from configured trusted proxies (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-fix-rate-limit-xff-spoofing
gh pr create --title "fix(security): only trust X-Forwarded-For from configured trusted proxies" --body "Closes #<issue-number>"
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Task 7: Minor Fixes — Actuator Permit + ObjectConverter Injection (Issues #8 + #9)

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCaseTest.kt`

**Context (Issue #8):** `SecurityConfig` permits `/actuator/**` wildcard. `application.yml` only exposes `health` and `info`. The wildcard means any future actuator endpoint added to the `include` list would be auto-exposed without security review. Tighten to exact paths.

**Context (Issue #9):** `RegisterPasskeyFinishUseCase` instantiates `private val objectConverter = ObjectConverter()` directly, ignoring the Spring `@Bean` in `WebAuthnConfig`. `AuthenticatePasskeyFinishUseCase` correctly injects it via constructor. Fix the inconsistency.

### Step 1: Create GitHub issue

```bash
gh issue create \
  --title "chore(security): tighten actuator permit to explicit paths; inject ObjectConverter in RegisterPasskeyFinishUseCase" \
  --body "Two minor issues:
1. SecurityConfig permits /actuator/** wildcard instead of explicit /actuator/health and /actuator/info
2. RegisterPasskeyFinishUseCase creates its own ObjectConverter() instead of injecting the Spring bean declared in WebAuthnConfig" \
  --label chore
```

### Step 2: Create branch

```bash
git checkout main
git checkout -b feature/<issue-number>-minor-security-cleanup
```

### Step 3: Fix actuator wildcard in `SecurityConfig`

In `src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt`, change:

```kotlin
// BEFORE
"/actuator/**",
```

to:

```kotlin
// AFTER
"/actuator/health", "/actuator/info",
```

### Step 4: Fix `ObjectConverter` injection in `RegisterPasskeyFinishUseCase`

In `src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt`:

1. Remove line 27: `private val objectConverter = ObjectConverter()`
2. Add `objectConverter: ObjectConverter` as a constructor parameter:

```kotlin
// BEFORE
@Component
class RegisterPasskeyFinishUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val credentialRepository: PasskeyCredentialRepository,
    private val webAuthnManager: WebAuthnManager,
    private val props: WebAuthnProperties,
) {
    private val objectConverter = ObjectConverter()
```

```kotlin
// AFTER
@Component
class RegisterPasskeyFinishUseCase(
    private val redisChallengeStore: RedisChallengeStore,
    private val credentialRepository: PasskeyCredentialRepository,
    private val webAuthnManager: WebAuthnManager,
    private val props: WebAuthnProperties,
    private val objectConverter: ObjectConverter,
) {
```

Remove the `import com.webauthn4j.converter.util.ObjectConverter` if it was only used for the direct instantiation (check — it's still needed for the type, so keep the import).

### Step 5: Update `RegisterPasskeyFinishUseCaseTest` to inject the converter

Open `src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCaseTest.kt`.

Find where `RegisterPasskeyFinishUseCase` is constructed in the test class and add an `objectConverter` mock:

```kotlin
private val objectConverter = mockk<ObjectConverter>().also {
    every { it.cborConverter } returns mockk(relaxed = true)
}

// Update the use case construction to include objectConverter:
private val useCase = RegisterPasskeyFinishUseCase(
    redisChallengeStore, credentialRepository, webAuthnManager, props, objectConverter
)
```

(Adjust to match the actual test file structure.)

### Step 6: Run the affected tests

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCaseTest"
./gradlew test --tests "com.aibles.iam.shared.config.*"
```

Expected: all pass.

### Step 7: Run full test suite

```bash
./gradlew test
```

### Step 8: Commit, push, PR, merge

```bash
git add \
  src/main/kotlin/com/aibles/iam/shared/config/SecurityConfig.kt \
  src/main/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCase.kt \
  src/test/kotlin/com/aibles/iam/authentication/usecase/RegisterPasskeyFinishUseCaseTest.kt
git commit -m "chore(security): tighten actuator permit; inject ObjectConverter in RegisterPasskeyFinishUseCase (Closes #<issue-number>)"
git push -u origin feature/<issue-number>-minor-security-cleanup
gh pr create --title "chore: tighten actuator permit; inject ObjectConverter in RegisterPasskeyFinishUseCase" --body "Closes #<issue-number>"
gh pr merge --squash --delete-branch
git checkout main && git pull origin main
```

---

## Final Verification

After all 7 tasks are merged:

```bash
git checkout main && git pull origin main
./gradlew test
```

Expected: full test suite passes with no failures.

Confirm in the output that these test classes all pass:
- `PasskeyCredentialTest` (4 tests including new zero-counter test)
- `SyncGoogleUserUseCaseTest` (4 tests — new class)
- `LoginWithGoogleUseCaseTest` (2 tests — refactored)
- `AuthenticatePasskeyFinishUseCaseTest` (5 tests including disabled-user ordering test)
- `RedisTokenStoreTest` (5 tests including user-set cleanup test)
- `RevokeTokenUseCaseTest` (includes revoke-all test)
- `RateLimitFilterTest` (6 tests including XFF spoofing tests)
