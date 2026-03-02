# IAM Service — Frontend Integration Guide

**Backend base URL:** `http://localhost:8080`
**Frontend dev URL:** `http://localhost:5173` (Vite default)
**Interactive API docs:** `http://localhost:8080/swagger-ui/index.html`

---

## Universal Response Envelope

Every endpoint returns the same wrapper:

```json
// Success
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": "2026-03-01T10:00:00Z"
}

// Failure
{
  "success": false,
  "data": null,
  "error": {
    "code": "USER_DISABLED",
    "message": "Account is disabled"
  },
  "timestamp": "2026-03-01T10:00:00Z"
}
```

Always check `response.data.success` before reading `data`. Read `error.code` for programmatic handling and `error.message` to show the user.

---

## Authentication Overview

The service supports two login methods. Both return the same token pair:

| Field | Type | Description |
|-------|------|-------------|
| `accessToken` | `string` | JWT — send in every authenticated request as `Authorization: Bearer <token>` |
| `refreshToken` | `string` | Opaque UUID — store securely, use to get new access token |
| `expiresIn` | `number` | Access token lifetime in **seconds** (default: 900 = 15 min) |

**Store tokens in memory** (not localStorage) to avoid XSS exposure. Use a refresh call before every user-visible session check.

---

## 1. Google OAuth2 Login

This is a full browser redirect flow — not an API call.

### Step 1 — Redirect the user

```js
window.location.href = 'http://localhost:8080/oauth2/authorization/google'
```

The backend redirects to Google, Google authenticates, then redirects back to the backend callback URL.

### Step 2 — Receive tokens

On success, the backend returns a JSON response **in the same browser window** (not a redirect back to your frontend):

```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "expiresIn": 900
  }
}
```

> **Handling the redirect:** Since the backend returns JSON directly in the browser window after Google redirects, you have two options:
> 1. **Popup approach** — open the Google login in a `window.open()` popup, post the tokens back to the main window via `postMessage`
> 2. **Same-window approach** — redirect the whole page, parse the JSON from the response body on return, then navigate to your app

### On failure

```json
{
  "success": false,
  "error": { "code": "GOOGLE_AUTH_FAILED", "message": "..." }
}
```

HTTP status: `401`

---

## 2. Passkey (WebAuthn) Flow

Passkey requires the **browser's WebAuthn API** (`navigator.credentials`). This cannot be done with plain HTTP calls. The flow is a two-step ceremony: **start** (get a challenge from the server) → browser prompts biometric → **finish** (send result back).

### 2a. Register a Passkey

The user must already be logged in (needs a valid `accessToken`).

#### Step 1 — POST `/api/v1/auth/passkey/register/start`

```http
POST /api/v1/auth/passkey/register/start
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "displayName": "My MacBook" }
```

`displayName` is optional — a friendly label shown in the browser's credential picker.

**Response:**
```json
{
  "success": true,
  "data": {
    "sessionId": "uuid-string",
    "rpId": "localhost",
    "rpName": "IAM Service Dev",
    "userId": "uuid-string",
    "userEmail": "user@example.com",
    "userDisplayName": "User Name",
    "challenge": "base64url-string",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "attestation": "none"
  }
}
```

#### Step 2 — Call the browser WebAuthn API

```js
async function registerPasskey(startData, jwt) {
  // Convert challenge from base64url to ArrayBuffer
  const challenge = base64urlToBuffer(startData.challenge)
  const userId = new TextEncoder().encode(startData.userId)

  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { id: startData.rpId, name: startData.rpName },
      user: {
        id: userId,
        name: startData.userEmail,
        displayName: startData.userDisplayName ?? startData.userEmail,
      },
      challenge,
      pubKeyCredParams: startData.pubKeyCredParams,
      timeout: startData.timeout,
      attestation: startData.attestation,
      authenticatorSelection: { userVerification: 'preferred' },
    },
  })

  // Step 3: send result to backend
  await fetch('/api/v1/auth/passkey/register/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${jwt}`,
    },
    body: JSON.stringify({
      sessionId: startData.sessionId,
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      attestationObject: bufferToBase64url(credential.response.attestationObject),
      displayName: 'My MacBook',  // optional
    }),
  })
}
```

#### Step 3 — POST `/api/v1/auth/passkey/register/finish`

```http
POST /api/v1/auth/passkey/register/finish
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "sessionId": "uuid from start response",
  "clientDataJSON": "base64url-string",
  "attestationObject": "base64url-string",
  "displayName": "My MacBook"
}
```

**Response on success:**
```json
{ "success": true, "data": null }
```

**Error codes:**
| Code | Meaning |
|------|---------|
| `PASSKEY_CHALLENGE_EXPIRED` | Session timed out (5 min limit) — call start again |
| `PASSKEY_ATTESTATION_FAILED` | Browser data failed verification |

---

### 2b. Authenticate with Passkey (Login)

This flow is unauthenticated — no token needed.

#### Step 1 — POST `/api/v1/auth/passkey/authenticate/start`

```http
POST /api/v1/auth/passkey/authenticate/start
```

No body, no auth header.

**Response:**
```json
{
  "success": true,
  "data": {
    "sessionId": "uuid-string",
    "rpId": "localhost",
    "challenge": "base64url-string",
    "timeout": 60000,
    "userVerification": "preferred"
  }
}
```

#### Step 2 — Call the browser WebAuthn API

```js
async function authenticatePasskey(startData) {
  const challenge = base64urlToBuffer(startData.challenge)

  const assertion = await navigator.credentials.get({
    publicKey: {
      rpId: startData.rpId,
      challenge,
      timeout: startData.timeout,
      userVerification: startData.userVerification,
    },
  })

  // Step 3: send assertion to backend
  const res = await fetch('/api/v1/auth/passkey/authenticate/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      credentialId: bufferToBase64url(assertion.rawId),
      sessionId: startData.sessionId,
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      signature: bufferToBase64url(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? bufferToBase64url(assertion.response.userHandle)
        : null,
    }),
  })
  return res.json()
}
```

#### Step 3 — POST `/api/v1/auth/passkey/authenticate/finish`

```http
POST /api/v1/auth/passkey/authenticate/finish
Content-Type: application/json

{
  "credentialId": "base64url-string",
  "sessionId": "uuid from start response",
  "clientDataJSON": "base64url-string",
  "authenticatorData": "base64url-string",
  "signature": "base64url-string",
  "userHandle": "base64url-string or null"
}
```

**Response on success — returns tokens:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiJ9...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "expiresIn": 900
  }
}
```

**Error codes:**
| Code | Meaning |
|------|---------|
| `PASSKEY_NOT_FOUND` | Credential not registered on this server |
| `PASSKEY_CHALLENGE_EXPIRED` | Session timed out — call start again |
| `PASSKEY_COUNTER_INVALID` | Possible cloned authenticator |
| `TOKEN_INVALID` | Signature verification failed |
| `USER_DISABLED` | Account has been disabled |

---

## 3. Token Management

### Refresh — POST `/api/v1/auth/refresh`

Call this before the access token expires (`expiresIn` seconds from issue time).
Each call rotates the refresh token — **save the new `refreshToken`** from the response.

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{ "refreshToken": "550e8400-e29b-41d4-a716-446655440000" }
```

**Response — new token pair:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiJ9...",
    "refreshToken": "new-uuid",
    "expiresIn": 900
  }
}
```

**Error:** `TOKEN_INVALID` (expired or already used) → send user to login.

### Logout — POST `/api/v1/auth/logout`

Revokes **all sessions** for the user (not just the current device).

```http
POST /api/v1/auth/logout
Content-Type: application/json

{ "refreshToken": "550e8400-e29b-41d4-a716-446655440000" }
```

**Response:** HTTP `204 No Content` (no body).

---

## 4. Passkey Credential Management

Requires valid `accessToken`.

### List registered passkeys — GET `/api/v1/auth/passkey/credentials`

```http
GET /api/v1/auth/passkey/credentials
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "credentialId": "base64url-string",
      "displayName": "My MacBook",
      "createdAt": "2026-03-01T10:00:00Z",
      "lastUsedAt": "2026-03-01T12:00:00Z"
    }
  ]
}
```

### Delete a passkey — DELETE `/api/v1/auth/passkey/credentials/{id}`

```http
DELETE /api/v1/auth/passkey/credentials/{id}
Authorization: Bearer <accessToken>
```

`{id}` is the `id` UUID from the list response (not `credentialId`).

**Response:** HTTP `204 No Content`.

**Error:** `PASSKEY_NOT_FOUND` or `FORBIDDEN` (trying to delete another user's credential).

---

## 5. Error Reference

| HTTP | Code | When it happens |
|------|------|----------------|
| 401 | `TOKEN_INVALID` | Missing/malformed JWT, or refresh token already consumed |
| 401 | `TOKEN_EXPIRED` | JWT past its expiry — call refresh |
| 401 | `TOKEN_REVOKED` | Token was explicitly revoked |
| 401 | `GOOGLE_AUTH_FAILED` | Google login failed |
| 403 | `USER_DISABLED` | Account disabled by admin |
| 400 | `PASSKEY_CHALLENGE_EXPIRED` | WebAuthn ceremony took too long (>5 min) |
| 400 | `PASSKEY_ATTESTATION_FAILED` | Registration data corrupted or tampered |
| 401 | `PASSKEY_COUNTER_INVALID` | Possible cloned authenticator |
| 404 | `PASSKEY_NOT_FOUND` | Credential ID not registered |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests — wait 60 seconds |

---

## 6. Utility Functions (copy-paste)

```js
// ArrayBuffer → base64url string (for sending to backend)
function bufferToBase64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')
}

// base64url string → ArrayBuffer (for feeding to navigator.credentials)
function base64urlToBuffer(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/')
  while (str.length % 4) str += '='
  return Uint8Array.from(atob(str), c => c.charCodeAt(0)).buffer
}
```

---

## 7. Recommended Auth Flow in Vue

```
App starts
  └─ has refreshToken in memory?
        ├─ YES → call /auth/refresh
        │          ├─ success → store new tokens, user is logged in
        │          └─ fail (TOKEN_INVALID) → clear tokens, show login page
        └─ NO  → show login page

Login page
  ├─ "Login with Google" button → window.location.href = /oauth2/authorization/google
  └─ "Login with Passkey" button → authenticatePasskey() → store tokens

Every API request
  └─ add header: Authorization: Bearer <accessToken>

On 401 TOKEN_EXPIRED response
  └─ call /auth/refresh → retry original request with new token

Logout button
  └─ call /auth/logout → clear tokens from memory → redirect to login
```

---

## 8. CORS Note

The backend is configured to allow requests from `http://localhost:5173`.
Make sure your Vue axios/fetch calls use `http://localhost:8080` as the base URL — **do not proxy through Vite** or the `Authorization` header may be stripped.

If you change the frontend port, update `CORS_ALLOWED_ORIGINS` and `WEBAUTHN_RP_ORIGIN` in `.env` and restart the backend.
