# Fix Deprecated webauthn4j API Usage Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Replace two deprecated webauthn4j 0.28.4 APIs in `AuthenticatePasskeyFinishUseCase` with their non-deprecated equivalents, with zero behaviour change.

**Architecture:** Single file change. `AuthenticatorImpl` (deprecated) is replaced by `CredentialRecordImpl` — both implement `Authenticator` (via `CredentialRecord extends Authenticator`), so it is a drop-in replacement. The deprecated two-boolean `AuthenticationParameters` constructor is replaced by the three-argument form that adds an explicit `allowCredentials: List<ByteArray>?` parameter (passed as `null` to allow any credential).

**Tech Stack:** webauthn4j-core 0.28.4, Kotlin 2.x, MockK, JUnit 5.

---

## Verified API Facts (from bytecode inspection)

### Deprecated (currently in use)

```kotlin
// Line 13
import com.webauthn4j.authenticator.AuthenticatorImpl

// Line 67
val authenticator = AuthenticatorImpl(attestedCredentialData, null, credential.signCounter)

// Line 83
val authParameters = AuthenticationParameters(serverProperty, authenticator, false, true)
```

### Non-deprecated replacements

**`CredentialRecordImpl` 10-arg constructor:**
```java
// com.webauthn4j.credential.CredentialRecordImpl
public CredentialRecordImpl(
    AttestationStatement,          // null  — not stored post-registration
    Boolean,                       // false — uvInitialized
    Boolean,                       // null  — backupEligible (unknown from stored record)
    Boolean,                       // null  — backupState   (unknown from stored record)
    long,                          // credential.signCounter
    AttestedCredentialData,        // attestedCredentialData
    AuthenticationExtensionsAuthenticatorOutputs<...>,  // null
    CollectedClientData,           // null  — not available at auth time
    AuthenticationExtensionsClientOutputs<...>,         // null
    Set<AuthenticatorTransport>,   // null
)
```

**`AuthenticationParameters` non-deprecated constructor (confirmed NOT deprecated by bytecode):**
```java
// descriptor: (ServerProperty; Authenticator; List; ZZ)V  — no Deprecated annotation
public AuthenticationParameters(
    ServerProperty serverProperty,
    Authenticator  authenticator,      // accepts CredentialRecordImpl (implements Authenticator)
    List<byte[]>   allowCredentials,   // null = allow any registered credential
    boolean        userVerificationRequired,
    boolean        userPresenceRequired,
)
```

---

## Task 1: Replace Deprecated webauthn4j Classes

**Branch:** `fix/deprecated-webauthn4j-authenticator-impl`

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt`

**Step 1.1: Run tests to confirm current state (deprecation warnings, but PASS)**

```bash
source ~/.sdkman/bin/sdkman-init.sh && sdk use java 24.0.2-amzn
./gradlew test --tests "com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCaseTest" 2>&1 | grep -E "PASSED|FAILED|warning"
# Expected: 4 tests PASSED with deprecation warnings about AuthenticatorImpl
```

**Step 1.2: Replace import**

In `AuthenticatePasskeyFinishUseCase.kt`, change line 13:

```kotlin
// BEFORE:
import com.webauthn4j.authenticator.AuthenticatorImpl

// AFTER:
import com.webauthn4j.credential.CredentialRecordImpl
```

**Step 1.3: Replace `AuthenticatorImpl` construction with `CredentialRecordImpl` (Step 3 comment block)**

Change lines 67 (the `val authenticator = ...` line):

```kotlin
// BEFORE:
val authenticator = AuthenticatorImpl(attestedCredentialData, null, credential.signCounter)

// AFTER:
val credentialRecord = CredentialRecordImpl(
    null,                    // attestationStatement — not stored post-registration
    false,                   // uvInitialized
    null,                    // backupEligible — unknown from stored credential
    null,                    // backupState — unknown from stored credential
    credential.signCounter,
    attestedCredentialData,
    null,                    // authenticatorExtensions
    null,                    // collectedClientData — not available at auth time
    null,                    // clientExtensions
    null,                    // authenticatorTransports
)
```

**Step 1.4: Replace deprecated `AuthenticationParameters` constructor (Step 4 comment block)**

Change line 83:

```kotlin
// BEFORE:
val authParameters = AuthenticationParameters(serverProperty, authenticator, false, true)

// AFTER:
val authParameters = AuthenticationParameters(serverProperty, credentialRecord, null, false, true)
```

Note: `null` for `allowCredentials` means "accept any registered credential" — correct for a login flow where the browser presents the credential ID.

**Step 1.5: Verify no compilation errors and no deprecation warnings**

```bash
./gradlew compileKotlin 2>&1 | grep -E "^w:|^e:|deprecated|Deprecated"
# Expected: ZERO lines — no warnings, no errors
```

**Step 1.6: Run the use case tests to verify GREEN**

```bash
./gradlew test --tests "com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCaseTest" 2>&1 | tail -5
# Expected: BUILD SUCCESSFUL — 4 tests PASSED
```

**Step 1.7: Run full test suite**

```bash
./gradlew test 2>&1 | tail -5
# Expected: BUILD SUCCESSFUL — zero failures
```

**Step 1.8: Commit and merge**

```bash
git add src/main/kotlin/com/aibles/iam/authentication/usecase/AuthenticatePasskeyFinishUseCase.kt
git commit -m "fix(authentication): replace deprecated AuthenticatorImpl with CredentialRecordImpl"
git push -u origin fix/deprecated-webauthn4j-authenticator-impl
gh pr create \
  --title "fix(authentication): replace deprecated webauthn4j AuthenticatorImpl with CredentialRecordImpl" \
  --body "Replaces deprecated \`AuthenticatorImpl\` with \`CredentialRecordImpl\` and the two-boolean \`AuthenticationParameters\` constructor with the non-deprecated \`allowCredentials\`-based variant. No behaviour change — CredentialRecord extends Authenticator. Zero test changes required." \
  --base main
gh pr merge <PR> --squash --delete-branch
git checkout main && git pull origin main
```

---

## Post-Verification

```bash
./gradlew compileKotlin 2>&1 | grep -c "deprecated"
# Expected: 0
```

**Definition of Done:**
- [ ] No deprecation warnings from `compileKotlin`
- [ ] `AuthenticatePasskeyFinishUseCaseTest`: all 4 tests still pass
- [ ] Full suite: `BUILD SUCCESSFUL`
- [ ] `AuthenticatorImpl` import removed from codebase
