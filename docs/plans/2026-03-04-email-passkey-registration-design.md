# Email + Passkey Registration — Design Document

**Date:** 2026-03-04
**Goal:** Allow users with an independent email (no Google account) to register with a passkey in a single combined flow.

---

## Problem

Currently, user creation only happens via Google OAuth2 login (`SyncGoogleUserUseCase` → `CreateUserUseCase`). Passkey registration requires an existing authenticated user. Users without a Google account cannot register.

## Decision

**Approach 1 (chosen):** New public registration endpoints under `/api/v1/auth/register/` — clean separation from the existing authenticated passkey registration flow.

**Rejected:** Extending existing endpoints with dual auth modes — too complex, harder to reason about security.

---

## Endpoints

All **public** (no JWT required):

```
POST /api/v1/auth/register/send-otp
  Request:  { "email": "user@example.com" }
  Response: 202 Accepted
  Guards:   email not already registered (409 EMAIL_ALREADY_REGISTERED),
            rate limit 3 sends / 10-min window (429 OTP_SEND_LIMIT_EXCEEDED)

POST /api/v1/auth/register/verify-otp
  Request:  { "email": "user@example.com", "code": "123456" }
  Response: { "otpToken": "..." }
  Guards:   max 3 attempts (429 OTP_MAX_ATTEMPTS),
            5-min code expiry (400 OTP_EXPIRED)

POST /api/v1/auth/register/passkey/start
  Request:  { "otpToken": "...", "displayName": "My device (optional)" }
  Response: WebAuthn PublicKeyCredentialCreationOptions
  Guards:   otpToken valid and not expired (10-min TTL)

POST /api/v1/auth/register/passkey/finish
  Request:  { "sessionId": "...", "clientDataJSON": "...", "attestationObject": "...", "displayName": "..." }
  Response: { "accessToken": "...", "refreshToken": "...", "expiresIn": 900 }
  Guards:   attestation valid, email still not registered (race condition guard)
  Action:   Creates User + PasskeyCredential atomically, issues JWT tokens
```

---

## RedisOtpStore Generalization

Add `OtpScope` enum to namespace Redis keys:

```kotlin
enum class OtpScope(val prefix: String) {
    PASSKEY_REG("otp:reg:"),
    SIGNUP("otp:signup:");
}
```

Change all methods from `UUID` to `(scope: OtpScope, key: String)`:
- `saveOtp(scope, key, code)` — stores code under `${scope.prefix}${key}`
- `getOtp(scope, key)` — retrieves code
- `deleteOtp(scope, key)` — deletes code + attempts
- `incrementAttempts(scope, key)` — increments attempt counter
- `incrementSendCount(scope, key)` — increments send counter
- `saveOtpToken(scope, token, value)` — stores token → value
- `consumeOtpToken(scope, token)` — consumes token (one-time)

Existing callers pass `OtpScope.PASSKEY_REG, userId.toString()`.
New registration callers pass `OtpScope.SIGNUP, email`.

Key format becomes: `otp:signup:user@example.com`, `otp:signup:attempts:user@example.com`, etc.

---

## WebAuthnCeremonyService Extraction

Extract shared WebAuthn logic from `RegisterPasskeyStartUseCase` and `RegisterPasskeyFinishUseCase` into:

```kotlin
@Component
class WebAuthnCeremonyService(
    private val template: StringRedisTemplate,
    private val webAuthnManager: WebAuthnManager,
    private val webAuthnProperties: WebAuthnProperties,
) {
    data class ChallengeData(
        val sessionId: String,
        val rpId: String,
        val rpName: String,
        val challenge: String,       // base64url
        val pubKeyCredParams: List<PubKeyCredParam>,
        val timeout: Long,
        val attestation: String,
    )

    data class VerifiedCredential(
        val credentialId: ByteArray,
        val coseKeyBytes: ByteArray,
        val counter: Long,
        val aaguid: AAGUID,
    )

    fun createChallenge(userIdentifier: String, displayName: String?): ChallengeData
    fun verifyAttestation(sessionId: String, clientDataJSON: String, attestationObject: String): VerifiedCredential
}
```

Both existing use cases and new registration use cases call these methods.

---

## Error Handling

**New error code:**
```kotlin
EMAIL_ALREADY_REGISTERED(HttpStatus.CONFLICT)
```

**Reused error codes:** `OTP_SEND_LIMIT_EXCEEDED`, `OTP_MAX_ATTEMPTS`, `OTP_EXPIRED`, `OTP_INVALID`, `PASSKEY_CHALLENGE_EXPIRED`, `PASSKEY_ATTESTATION_FAILED`.

**Race condition:** `FinishRegistrationUseCase` does a final `userRepository.existsByEmail()` check before creating the user. If email was registered between send-otp and finish → `EMAIL_ALREADY_REGISTERED`.

**Email enumeration:** `send-otp` returns 409 CONFLICT if email exists. Acceptable for this use case (B2B/internal app).

---

## Security

- All 4 endpoints added to `SecurityConfig.permitAll()`
- Rate limiting via existing `RateLimitFilter`
- OTP keyed by email (not userId, since no user exists yet)
- OTP token carries verified email through the chain
- Separate Redis namespace (`otp:signup:`) prevents collision with passkey OTPs

---

## Files

### Modified
| File | Change |
|---|---|
| `RedisOtpStore.kt` | Add `OtpScope` enum, change all methods to `(scope, key: String)` |
| `RedisOtpStoreTest.kt` | Update existing tests for new signature, add SIGNUP scope tests |
| `SendPasskeyOtpUseCase.kt` | Pass `OtpScope.PASSKEY_REG, userId.toString()` |
| `VerifyPasskeyOtpUseCase.kt` | Same |
| `RegisterPasskeyStartUseCase.kt` | Delegate to `WebAuthnCeremonyService` |
| `RegisterPasskeyFinishUseCase.kt` | Delegate to `WebAuthnCeremonyService` |
| `SecurityConfig.kt` | Add `/api/v1/auth/register/**` to permitAll |
| `ErrorCode.kt` | Add `EMAIL_ALREADY_REGISTERED` |

### New
| File | Purpose |
|---|---|
| `WebAuthnCeremonyService.kt` | Shared challenge generation + attestation verification |
| `RegisterController.kt` | 4 public endpoints under `/api/v1/auth/register` |
| `SendRegistrationOtpUseCase.kt` | Check email not taken, send OTP |
| `VerifyRegistrationOtpUseCase.kt` | Verify OTP, issue token keyed by email |
| `StartRegistrationUseCase.kt` | Consume OTP token, create WebAuthn challenge |
| `FinishRegistrationUseCase.kt` | Verify attestation, create User + PasskeyCredential, issue tokens |
| `RegisterSendOtpRequest.kt` | DTO: `{ email }` |
| `RegisterVerifyOtpRequest.kt` | DTO: `{ email, code }` |
| `RegisterStartRequest.kt` (new, for register flow) | DTO: `{ otpToken, displayName? }` |
| Tests for each new use case | Unit tests (MockK) |

### Testing
- Unit tests for each new use case (MockK)
- Update existing `RedisOtpStoreTest` for new method signatures
- All existing tests must pass with identical behavior
- Integration test: full send-otp → verify → start → finish with Testcontainers
