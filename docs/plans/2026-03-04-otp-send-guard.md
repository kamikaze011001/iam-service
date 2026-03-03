# OTP Send Guard Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a per-user OTP send-rate limit (max 3 sends per 10-minute window) and a blank-email guard to `SendPasskeyOtpUseCase`.

**Architecture:** Two defenses added purely in `SendPasskeyOtpUseCase` and `RedisOtpStore`.
`RedisOtpStore` gains `incrementSendCount` using a new Redis key prefix `otp:reg:sends:` with a 10-minute TTL.
The send counter is **independent** from the verify-attempts counter and is **never reset** by `saveOtp`.
`SendPasskeyOtpUseCase.execute()` checks blank-email first, then send-limit, before generating/storing the OTP.
No new endpoints, no controller changes.

**Tech Stack:** Kotlin 2.x, Spring Boot 3.4.x, Spring Data Redis (Lettuce), JUnit 5, MockK, Testcontainers (Redis)

---

### Workflow Setup

**Before Task 1 — create the feature branch:**

```bash
git checkout main
git checkout -b feature/otp-send-guard
```

---

### Task 1: Add `OTP_SEND_LIMIT_EXCEEDED` error code + `incrementSendCount` to `RedisOtpStore`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`
- Modify: `src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt`

**Step 1: Write the failing tests in `RedisOtpStoreTest.kt`**

Open `src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt`.
Add two test cases at the end of the class body (before the closing `}`):

```kotlin
@Test
fun `incrementSendCount increments on each call`() {
    val userId = UUID.randomUUID()

    assertThat(store.incrementSendCount(userId)).isEqualTo(1L)
    assertThat(store.incrementSendCount(userId)).isEqualTo(2L)
    assertThat(store.incrementSendCount(userId)).isEqualTo(3L)
}

@Test
fun `incrementSendCount is independent per user`() {
    val userA = UUID.randomUUID()
    val userB = UUID.randomUUID()

    store.incrementSendCount(userA)
    store.incrementSendCount(userA)

    assertThat(store.incrementSendCount(userB)).isEqualTo(1L)
}
```

**Step 2: Run to confirm tests FAIL (compile error)**

```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisOtpStoreTest"
```
Expected: compilation fails — `incrementSendCount` not yet defined.

**Step 3: Add `OTP_SEND_LIMIT_EXCEEDED` to `ErrorCode.kt`**

Open `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`.
Add after `OTP_MAX_ATTEMPTS`:

```kotlin
OTP_SEND_LIMIT_EXCEEDED(HttpStatus.TOO_MANY_REQUESTS),
```

**Step 4: Add send-count constants and method to `RedisOtpStore.kt`**

Open `src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt`.

Add to `companion object` (after the existing constants):
```kotlin
private const val SEND_PREFIX = "otp:reg:sends:"
private val SEND_TTL          = Duration.ofMinutes(10)
const val MAX_SEND_COUNT      = 3L
```

Add after `val maxAttempts`:
```kotlin
val maxSendCount: Long get() = MAX_SEND_COUNT

/** Increments and returns the new send count within the 10-minute window. */
fun incrementSendCount(userId: UUID): Long {
    val key = "$SEND_PREFIX$userId"
    val count = template.opsForValue().increment(key) ?: 1L
    if (count == 1L) template.expire(key, SEND_TTL)
    return count
}
```

**Step 5: Run tests to confirm they PASS**

```bash
./gradlew test --tests "com.aibles.iam.authentication.infra.RedisOtpStoreTest"
```
Expected: `BUILD SUCCESSFUL`, all `RedisOtpStoreTest` tests pass.

**Step 6: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt \
        src/main/kotlin/com/aibles/iam/authentication/infra/RedisOtpStore.kt \
        src/test/kotlin/com/aibles/iam/authentication/infra/RedisOtpStoreTest.kt
git commit -m "feat(otp): add OTP_SEND_LIMIT_EXCEEDED error code and incrementSendCount to RedisOtpStore"
```

---

### Task 2: Add email-blank guard + send-limit check to `SendPasskeyOtpUseCase`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt`
- Modify: `src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt`

**Step 1: Write the two new failing tests in `SendPasskeyOtpUseCaseTest.kt`**

Open `src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt`.

Add these imports at the top (after the existing imports):
```kotlin
import com.aibles.iam.authentication.infra.RedisOtpStore
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import org.assertj.core.api.Assertions.assertThatThrownBy
```

Add two test cases after the existing test:

```kotlin
@Test
fun `throws BAD_REQUEST when user email is blank`() {
    val userId = UUID.randomUUID()
    val user = mockk<User> { every { email } returns "" }
    every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user

    assertThatThrownBy { useCase.execute(SendPasskeyOtpUseCase.Command(userId)) }
        .isInstanceOf(BadRequestException::class.java)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.BAD_REQUEST)

    verify(exactly = 0) { otpStore.incrementSendCount(any()) }
    verify(exactly = 0) { emailService.sendOtp(any(), any()) }
}

@Test
fun `throws OTP_SEND_LIMIT_EXCEEDED when send count exceeds limit`() {
    val userId = UUID.randomUUID()
    val user = mockk<User> { every { email } returns "user@test.com" }
    every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns user
    every { otpStore.incrementSendCount(userId) } returns RedisOtpStore.MAX_SEND_COUNT + 1
    every { otpStore.maxSendCount } returns RedisOtpStore.MAX_SEND_COUNT

    assertThatThrownBy { useCase.execute(SendPasskeyOtpUseCase.Command(userId)) }
        .isInstanceOf(BadRequestException::class.java)
        .extracting("errorCode")
        .isEqualTo(ErrorCode.OTP_SEND_LIMIT_EXCEEDED)

    verify(exactly = 0) { otpStore.saveOtp(any(), any()) }
    verify(exactly = 0) { emailService.sendOtp(any(), any()) }
}
```

Note: `otpStore` is declared as `mockk<RedisOtpStore>(relaxed = true)` — un-stubbed calls return default values
(`incrementSendCount` returns `0L`, `maxSendCount` returns `0L`). The existing passing test is unaffected
because `0L > 0L` is false. The new limit test stubs the count above the max explicitly.

**Step 2: Run to confirm new tests FAIL**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.SendPasskeyOtpUseCaseTest"
```
Expected: 2 new tests FAIL (guards not implemented yet), existing test still PASSES.

**Step 3: Implement the guards in `SendPasskeyOtpUseCase.execute()`**

Open `src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt`.

Add imports (after the existing imports):
```kotlin
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
```

Replace the entire `execute` body:
```kotlin
fun execute(command: Command) {
    val user = getUserUseCase.execute(GetUserUseCase.Query(command.userId))

    if (user.email.isBlank()) {
        throw BadRequestException("User has no verified email address.", ErrorCode.BAD_REQUEST)
    }

    val sends = otpStore.incrementSendCount(command.userId)
    if (sends > otpStore.maxSendCount) {
        throw BadRequestException("Too many OTP requests. Please try again later.", ErrorCode.OTP_SEND_LIMIT_EXCEEDED)
    }

    val code = String.format("%06d", random.nextInt(1_000_000))
    otpStore.saveOtp(command.userId, code)
    emailService.sendOtp(user.email, code)
}
```

**Step 4: Run all `SendPasskeyOtpUseCaseTest` tests to confirm they PASS**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.SendPasskeyOtpUseCaseTest"
```
Expected: `BUILD SUCCESSFUL`, all 3 tests pass.

**Step 5: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCase.kt \
        src/test/kotlin/com/aibles/iam/authentication/usecase/SendPasskeyOtpUseCaseTest.kt
git commit -m "feat(otp): guard blank email and enforce per-user OTP send-rate limit in SendPasskeyOtpUseCase"
```

---

### Task 3: Full test suite verification + PR

**Step 1: Run full test suite**

```bash
./gradlew test
```
Expected: `BUILD SUCCESSFUL`, all tests pass (129 existing + 4 new = 133 total).

**Step 2: Push branch and create PR**

```bash
git push -u origin feature/otp-send-guard

gh pr create \
  --title "feat(otp): per-user send-rate limit and blank-email guard for send-otp endpoint" \
  --body "$(cat <<'EOF'
## Summary
- Add `OTP_SEND_LIMIT_EXCEEDED (429)` error code
- `RedisOtpStore.incrementSendCount()` tracks sends per user in a 10-min Redis window (max 3)
- `SendPasskeyOtpUseCase` rejects blank email with `BAD_REQUEST` and exceeding send count with `OTP_SEND_LIMIT_EXCEEDED`

## Test Plan
- [x] `RedisOtpStoreTest` — 2 new Testcontainers integration tests for `incrementSendCount`
- [x] `SendPasskeyOtpUseCaseTest` — 2 new unit tests: blank-email guard and send-limit guard
- [x] Full suite passes (133/133)

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
