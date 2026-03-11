# IAM Service — Frontend Integration Guide

Everything a **Vue / Nuxt** frontend team needs to integrate with the IAM Service backend.

**Backend base URL:** `http://localhost:8080`
**Interactive API docs:** `http://localhost:8080/swagger-ui/index.html`

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Authentication Flows](#2-authentication-flows)
   - [2A. Google OAuth2 Popup Login](#2a-google-oauth2-popup-login)
   - [2B. Passkey Authentication](#2b-passkey-webauthn-authentication)
   - [2C. Passkey Registration (Authenticated)](#2c-passkey-registration-authenticated--with-otp-gate)
   - [2D. Passkey Credential Management](#2d-passkey-credential-management-authenticated)
   - [2E. Email + Passkey Self-Registration (Public)](#2e-email--passkey-self-registration-public)
3. [Token Management](#3-token-management)
4. [User Management](#4-user-management)
5. [Audit Logs](#5-audit-logs)
6. [OAuth2/OIDC Authorization Server (SSO)](#6-oauth2oidc-authorization-server-sso)
7. [Error Codes Reference](#7-error-codes-reference)
8. [Complete Endpoint Reference](#8-complete-endpoint-reference)
9. [JWT Access Token Claims](#9-jwt-access-token-claims)
10. [Utility Functions](#10-utility-functions)
11. [Environment Checklist](#11-environment-checklist)

---

## 1. Quick Start

### Response Envelope

**Every** API response is wrapped in `ApiResponse<T>`:

```json
// Success
{
  "success": true,
  "data": { ... },
  "error": null,
  "timestamp": "2026-03-04T10:30:00Z"
}

// Error
{
  "success": false,
  "data": null,
  "error": { "code": "USER_NOT_FOUND", "message": "User not found" },
  "timestamp": "2026-03-04T10:30:00Z"
}
```

Always check `response.data.success` before reading `data`. Use `error.code` for programmatic handling and `error.message` to show the user.

Paginated endpoints wrap `PageResponse<T>` inside `data`:

```json
{
  "success": true,
  "data": {
    "content": [ ... ],
    "page": 0,
    "size": 20,
    "totalElements": 100,
    "totalPages": 5
  }
}
```

### Auth Model

| Field          | Type     | Description                                                        |
|----------------|----------|--------------------------------------------------------------------|
| `accessToken`  | `string` | JWT (RS256) — send as `Authorization: Bearer <token>` on every authenticated request |
| `refreshToken` | `string` | Opaque UUID — store securely, use to get new access token          |
| `expiresIn`    | `number` | Access token lifetime in **seconds** (default: 900 = 15 min)      |

- **Refresh token** — 30-day TTL, **single-use** (rotated on each refresh call)
- **CSRF** — disabled (stateless JWT, no cookies)
- **Store tokens in memory** (Pinia store), not localStorage, to avoid XSS exposure

### CORS

Backend allows origins from `CORS_ALLOWED_ORIGINS` env var (default `http://localhost:3000`).

- Methods: `GET, POST, PATCH, DELETE, OPTIONS`
- Headers: `Authorization, Content-Type`
- Max-Age: 3600s

If you change the frontend port, update `CORS_ALLOWED_ORIGINS` in `.env` and restart the backend.

---

## 2. Authentication Flows

### 2A. Google OAuth2 Popup Login

The backend handles the full OAuth2 code exchange. The frontend opens a popup and listens for a `postMessage`.

#### Flow

```
Frontend                  Popup Window             IAM Backend              Google
   │                          │                        │                      │
   ├── window.open() ────────>│                        │                      │
   │                          ├── GET /oauth2/auth... ─>│                      │
   │                          │                        ├── redirect ──────────>│
   │                          │                        │<── callback + code ───┤
   │                          │                        ├── exchange code       │
   │                          │                        ├── sync user           │
   │                          │                        ├── issue tokens        │
   │                          │<── HTML + postMessage ──┤                      │
   │<── postMessage(tokens) ──┤                        │                      │
   │                          ├── window.close()       │                      │
```

#### Vue 3 Composable

```typescript
// composables/useGoogleLogin.ts
export function useGoogleLogin(backendUrl: string) {
  function login(): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
    return new Promise((resolve, reject) => {
      const width = 500, height = 600
      const left = window.screenX + (window.innerWidth - width) / 2
      const top = window.screenY + (window.innerHeight - height) / 2

      const popup = window.open(
        `${backendUrl}/oauth2/authorization/google`,
        'google-login',
        `width=${width},height=${height},left=${left},top=${top}`
      )

      function onMessage(event: MessageEvent) {
        if (event.origin !== backendUrl) return
        window.removeEventListener('message', onMessage)

        if (event.data.type === 'GOOGLE_AUTH_SUCCESS') {
          resolve({
            accessToken: event.data.accessToken,
            refreshToken: event.data.refreshToken,
            expiresIn: event.data.expiresIn,
          })
        } else if (event.data.type === 'GOOGLE_AUTH_ERROR') {
          reject(new Error(event.data.message))
        }
      }

      window.addEventListener('message', onMessage)

      // Poll for manual close
      const timer = setInterval(() => {
        if (popup?.closed) {
          clearInterval(timer)
          window.removeEventListener('message', onMessage)
          reject(new Error('Login cancelled'))
        }
      }, 500)
    })
  }

  return { login }
}
```

#### postMessage Payloads

**Success:**
```json
{
  "type": "GOOGLE_AUTH_SUCCESS",
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "expiresIn": 900
}
```

**Error:**
```json
{
  "type": "GOOGLE_AUTH_ERROR",
  "message": "Authentication failed"
}
```

---

### 2B. Passkey (WebAuthn) Authentication

Passkey login is a two-step challenge-response. **No JWT required.**

#### Step 1 — Start (get challenge)

```http
POST /api/v1/auth/passkey/authenticate/start
```

No request body.

**Response:**
```json
{
  "success": true,
  "data": {
    "sessionId": "a1b2c3d4-...",
    "rpId": "localhost",
    "challenge": "base64url-encoded-challenge",
    "timeout": 60000,
    "userVerification": "preferred"
  }
}
```

#### Step 2 — Finish (verify assertion)

```http
POST /api/v1/auth/passkey/authenticate/finish
Content-Type: application/json

{
  "credentialId": "base64url-credential-id",
  "sessionId": "a1b2c3d4-...",
  "clientDataJSON": "base64url-encoded",
  "authenticatorData": "base64url-encoded",
  "signature": "base64url-encoded",
  "userHandle": "base64url-encoded (optional)"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "550e8400-...",
    "expiresIn": 900
  }
}
```

**Error codes:** `PASSKEY_NOT_FOUND`, `PASSKEY_CHALLENGE_EXPIRED`, `PASSKEY_COUNTER_INVALID`, `USER_DISABLED`

---

### 2C. Passkey Registration (Authenticated — with OTP Gate)

Requires a valid JWT. The user must verify their email via OTP before registering a passkey.

#### Registration Flow

```
Frontend                        IAM Backend                     Email
   │                                │                             │
   ├── POST /register/send-otp ────>│                             │
   │   (JWT)                        ├── send 6-digit code ───────>│
   │                                │                             │
   │   (user reads email)           │                             │
   │                                │                             │
   ├── POST /register/verify-otp ──>│                             │
   │   {code: "123456"}             │                             │
   │<── {otpToken: "xxx"} ──────────┤                             │
   │                                │                             │
   ├── POST /register/start ───────>│                             │
   │   {otpToken: "xxx"}            │                             │
   │<── WebAuthn creation options ──┤                             │
   │                                │                             │
   ├── navigator.credentials.create()                             │
   │                                │                             │
   ├── POST /register/finish ──────>│                             │
   │   {attestation data}           │                             │
   │<── 200 OK ─────────────────────┤                             │
```

#### Send OTP

```http
POST /api/v1/auth/passkey/register/send-otp
Authorization: Bearer <accessToken>
```

No body. Sends a 6-digit code to the user's email.

**Rate limit:** Max 3 sends per 10-minute window. Error: `OTP_SEND_LIMIT_EXCEEDED (429)`.

#### Verify OTP

```http
POST /api/v1/auth/passkey/register/verify-otp
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "code": "123456" }
```

**Response:**
```json
{ "success": true, "data": { "otpToken": "one-time-token" } }
```

- Code must be exactly 6 digits
- OTP expires after 5 minutes → `OTP_EXPIRED (400)`
- Max 3 wrong attempts → `OTP_MAX_ATTEMPTS (429)`, must resend

#### Start Registration

```http
POST /api/v1/auth/passkey/register/start
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "otpToken": "one-time-token", "displayName": "My YubiKey (optional)" }
```

**Response — WebAuthn `PublicKeyCredentialCreationOptions`:**
```json
{
  "success": true,
  "data": {
    "sessionId": "uuid",
    "rpId": "localhost",
    "rpName": "IAM Service",
    "userId": "uuid",
    "userEmail": "user@example.com",
    "userDisplayName": "John",
    "challenge": "base64url",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "attestation": "none"
  }
}
```

#### Finish Registration

```http
POST /api/v1/auth/passkey/register/finish
Authorization: Bearer <accessToken>
Content-Type: application/json

{
  "sessionId": "uuid",
  "clientDataJSON": "base64url",
  "attestationObject": "base64url",
  "displayName": "My YubiKey (optional)"
}
```

**Response:** `{ "success": true, "data": null }`

**Error codes:** `PASSKEY_CHALLENGE_EXPIRED`, `PASSKEY_ATTESTATION_FAILED`

---

### 2D. Passkey Credential Management (Authenticated)

#### List credentials

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
      "credentialId": "base64url",
      "displayName": "My YubiKey",
      "createdAt": "2026-03-01T12:00:00Z",
      "lastUsedAt": "2026-03-04T08:00:00Z"
    }
  ]
}
```

#### Delete credential

```http
DELETE /api/v1/auth/passkey/credentials/{id}
Authorization: Bearer <accessToken>
```

`{id}` is the `id` UUID from the list response (not `credentialId`).

**Response:** `204 No Content`

---

### 2E. Email + Passkey Self-Registration (Public)

A brand-new user with no existing account registers using their email (OTP verification) then enrolls a passkey. **No JWT is required at any step.** On success, the user is created and tokens are issued immediately — no separate login step needed.

> **Difference from 2C:** Section 2C adds a passkey to an *already-authenticated* user's account. This flow creates a *new* user from scratch.

#### Registration Flow

```
Frontend                        IAM Backend                     Email
   │                                │                             │
   ├── POST /auth/register/send-otp >│                             │
   │   {email: "new@example.com"}   ├── check email not taken     │
   │                                ├── send 6-digit OTP ────────>│
   │<── 202 Accepted ───────────────┤                             │
   │                                │                             │
   │   (user reads email)           │                             │
   │                                │                             │
   ├── POST /auth/register/verify-otp>│                            │
   │   {email, code: "123456"}      │                             │
   │<── {otpToken: "xxx"} ──────────┤                             │
   │                                │                             │
   ├── POST /auth/register/passkey/start>│                         │
   │   {otpToken: "xxx"}            ├── consume token             │
   │                                ├── create WebAuthn challenge  │
   │                                ├── store email in session     │
   │<── WebAuthn creation options ──┤                             │
   │                                │                             │
   ├── navigator.credentials.create()                             │
   │                                │                             │
   ├── POST /auth/register/passkey/finish>│                        │
   │   {sessionId, attestation...}  ├── retrieve email from session│
   │                                ├── verify attestation         │
   │                                ├── create user                │
   │                                ├── save passkey               │
   │                                ├── issue tokens               │
   │<── {accessToken, refreshToken} ┤                             │
```

#### Step 1 — Send OTP

```http
POST /api/v1/auth/register/send-otp
Content-Type: application/json

{ "email": "new@example.com" }
```

**Response:** `202 Accepted`
```json
{ "success": true, "data": null }
```

**Errors:**
- `EMAIL_ALREADY_REGISTERED (409)` — email is taken; redirect to login
- `OTP_SEND_LIMIT_EXCEEDED (429)` — max 3 sends per 10-minute window

#### Step 2 — Verify OTP

```http
POST /api/v1/auth/register/verify-otp
Content-Type: application/json

{ "email": "new@example.com", "code": "123456" }
```

- `email` — must be a valid email
- `code` — exactly 6 digits

**Response:**
```json
{ "success": true, "data": { "otpToken": "one-time-token-uuid" } }
```

**Errors:**
- `OTP_INVALID (400)` — wrong code
- `OTP_EXPIRED (400)` — OTP has expired (5-min TTL); must resend
- `OTP_MAX_ATTEMPTS (429)` — 3 wrong attempts; must call send-otp again

#### Step 3 — Start Passkey Registration

```http
POST /api/v1/auth/register/passkey/start
Content-Type: application/json

{ "otpToken": "one-time-token-uuid", "displayName": "My YubiKey (optional)" }
```

**Response — WebAuthn `PublicKeyCredentialCreationOptions`:**
```json
{
  "success": true,
  "data": {
    "sessionId": "uuid",
    "rpId": "localhost",
    "rpName": "IAM Service",
    "email": "new@example.com",
    "challenge": "base64url-encoded-random-bytes",
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7 },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 60000,
    "attestation": "none"
  }
}
```

**Errors:**
- `OTP_EXPIRED (400)` — `otpToken` already consumed or expired; restart from step 2

#### Step 4 — Finish Passkey Registration

```http
POST /api/v1/auth/register/passkey/finish
Content-Type: application/json

{
  "sessionId": "uuid from start response",
  "clientDataJSON": "base64url",
  "attestationObject": "base64url",
  "displayName": "My YubiKey (optional)"
}
```

> **Note:** Do not send `email` — the backend retrieves it from the challenge session created in step 3.

**Response — tokens issued immediately:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJSUzI1NiIs...",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
    "expiresIn": 900
  }
}
```

**Errors:**
- `PASSKEY_CHALLENGE_EXPIRED (400)` — session expired (5-min TTL); restart from step 3
- `PASSKEY_ATTESTATION_FAILED (400)` — WebAuthn verification failed
- `EMAIL_ALREADY_REGISTERED (409)` — race condition; email registered between steps 1 and 4

#### Vue 3 Composable

```typescript
// composables/useEmailPasskeyRegister.ts
import { bufferToBase64url, base64urlToBuffer } from '~/utils/webauthn'

export function useEmailPasskeyRegister(api: AxiosInstance) {

  async function sendOtp(email: string) {
    await api.post('/api/v1/auth/register/send-otp', { email })
    // 202 Accepted — OTP sent to email
  }

  async function verifyOtp(email: string, code: string): Promise<string> {
    const res = await api.post('/api/v1/auth/register/verify-otp', { email, code })
    return res.data.data.otpToken
  }

  async function register(otpToken: string, displayName?: string) {
    // Step 3 — get WebAuthn challenge
    const startRes = await api.post('/api/v1/auth/register/passkey/start', {
      otpToken,
      displayName,
    })
    const opts = startRes.data.data

    // Step 3b — call browser API
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: base64urlToBuffer(opts.challenge),
        rp: { id: opts.rpId, name: opts.rpName },
        user: {
          id: new TextEncoder().encode(opts.email),  // opaque bytes for the authenticator
          name: opts.email,
          displayName: opts.email,
        },
        pubKeyCredParams: opts.pubKeyCredParams,
        timeout: opts.timeout,
        attestation: opts.attestation,
      },
    }) as PublicKeyCredential

    const response = credential.response as AuthenticatorAttestationResponse

    // Step 4 — finish
    const finishRes = await api.post('/api/v1/auth/register/passkey/finish', {
      sessionId: opts.sessionId,
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      displayName,
    })

    return finishRes.data.data  // { accessToken, refreshToken, expiresIn }
  }

  return { sendOtp, verifyOtp, register }
}
```

#### Registration Page Flow

```typescript
// pages/register.vue
const { sendOtp, verifyOtp, register } = useEmailPasskeyRegister(api)
const auth = useAuthStore()

// 1. User submits email form
async function onEmailSubmit(email: string) {
  try {
    await sendOtp(email)
    step.value = 'verify-otp'
  } catch (e) {
    if (e.response?.data?.error?.code === 'EMAIL_ALREADY_REGISTERED') {
      // Redirect to login — account exists
      router.push('/login')
    }
  }
}

// 2. User submits 6-digit code
async function onOtpSubmit(email: string, code: string) {
  otpToken.value = await verifyOtp(email, code)
  step.value = 'register-passkey'
}

// 3. User clicks "Register Passkey" button
async function onRegisterPasskey(displayName?: string) {
  const tokens = await register(otpToken.value, displayName)
  auth.setTokens(tokens)
  router.push('/dashboard')
}
```

---

## 3. Token Management

### Pinia Store

```typescript
// stores/auth.ts
import { defineStore } from 'pinia'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    accessToken: null as string | null,
    refreshToken: null as string | null,
    expiresAt: 0,
  }),
  getters: {
    isAuthenticated: (state) => !!state.accessToken && Date.now() < state.expiresAt,
  },
  actions: {
    setTokens(tokens: { accessToken: string; refreshToken: string; expiresIn: number }) {
      this.accessToken = tokens.accessToken
      this.refreshToken = tokens.refreshToken
      this.expiresAt = Date.now() + tokens.expiresIn * 1000
    },
    clear() {
      this.accessToken = null
      this.refreshToken = null
      this.expiresAt = 0
    },
  },
})
```

### Refresh Token

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{ "refreshToken": "550e8400-e29b-41d4-a716-446655440000" }
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGci...",
    "refreshToken": "new-uuid",
    "expiresIn": 900
  }
}
```

> **Single-use refresh tokens.** Each refresh token can only be used once. Always store the **new** `refreshToken` from the response. If a refresh fails with `TOKEN_REVOKED`, the user must re-authenticate.

### Logout

```http
POST /api/v1/auth/logout
Content-Type: application/json

{ "refreshToken": "550e8400-e29b-41d4-a716-446655440000" }
```

**Response:** `204 No Content`. Revokes all refresh tokens for the user.

### Axios Interceptor (Auto-Refresh)

```typescript
// plugins/api.ts
import axios from 'axios'
import { useAuthStore } from '~/stores/auth'

const api = axios.create({ baseURL: 'http://localhost:8080' })

api.interceptors.request.use((config) => {
  const auth = useAuthStore()
  if (auth.accessToken) {
    config.headers.Authorization = `Bearer ${auth.accessToken}`
  }
  return config
})

let refreshPromise: Promise<void> | null = null

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const auth = useAuthStore()
    if (error.response?.status === 401 && auth.refreshToken) {
      if (!refreshPromise) {
        refreshPromise = api
          .post('/api/v1/auth/refresh', { refreshToken: auth.refreshToken })
          .then((res) => auth.setTokens(res.data.data))
          .catch(() => {
            auth.clear()
            navigateTo('/login')
          })
          .finally(() => { refreshPromise = null })
      }
      await refreshPromise
      return api(error.config)
    }
    return Promise.reject(error)
  }
)

export default api
```

### Recommended Auth Flow

```
App starts
  └─ has refreshToken in memory?
        ├─ YES → call /auth/refresh
        │          ├─ success → store new tokens, user is logged in
        │          └─ fail (TOKEN_INVALID) → clear tokens, show login page
        └─ NO  → show login page

Login page
  ├─ "Login with Google" → useGoogleLogin() popup flow
  ├─ "Login with Passkey" → authenticatePasskey() → store tokens
  └─ "Create account" → useEmailPasskeyRegister() 4-step flow → store tokens

Every API request
  └─ Axios interceptor adds Authorization: Bearer <accessToken>

On 401 response
  └─ interceptor calls /auth/refresh → retries original request

Logout button
  └─ call /auth/logout → clear tokens → redirect to login
```

---

## 4. User Management (Authenticated)

All endpoints require JWT.

### Get User

```http
GET /api/v1/users/{id}
Authorization: Bearer <accessToken>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "email": "user@example.com",
    "displayName": "John Doe",
    "status": "ACTIVE",
    "createdAt": "2026-03-01T12:00:00Z",
    "updatedAt": "2026-03-04T08:00:00Z"
  }
}
```

### Create User

```http
POST /api/v1/users
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "email": "user@example.com", "displayName": "John Doe" }
```

- `email` — required, must be a valid email
- `displayName` — optional

### Update User

```http
PATCH /api/v1/users/{id}
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "displayName": "Jane Doe" }
```

- `displayName` — required, non-blank

### Change User Status

```http
PATCH /api/v1/users/{id}/status
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "status": "DISABLED" }
```

Valid values: `ACTIVE`, `DISABLED`.

### Delete User

```http
DELETE /api/v1/users/{id}
Authorization: Bearer <accessToken>
```

**Response:** `204 No Content`

---

## 5. Audit Logs (Authenticated)

```http
GET /api/v1/audit-logs
Authorization: Bearer <accessToken>
```

### Query Parameters

| Param       | Type     | Default | Description              |
|-------------|----------|---------|-----------------------------|
| `eventType` | string   | —       | Filter by audit event type |
| `userId`    | UUID     | —       | Filter by user           |
| `from`      | ISO 8601 | —       | Start date (inclusive)   |
| `to`        | ISO 8601 | —       | End date (inclusive)     |
| `page`      | int      | 0       | Zero-indexed page        |
| `size`      | int      | 20      | Results per page         |

### Response

```json
{
  "success": true,
  "data": {
    "content": [
      {
        "id": "uuid",
        "eventType": "GOOGLE_LOGIN_SUCCESS",
        "userId": "uuid",
        "actorId": "uuid",
        "ipAddress": "127.0.0.1",
        "userAgent": "Mozilla/5.0 ...",
        "metadata": { "email": "user@example.com" },
        "createdAt": "2026-03-04T10:30:00Z"
      }
    ],
    "page": 0,
    "size": 20,
    "totalElements": 42,
    "totalPages": 3
  }
}
```

---

## 6. OAuth2/OIDC Authorization Server (SSO)

The IAM service also acts as a **Spring Authorization Server** for third-party or internal apps to integrate via standard OAuth2/OIDC.

### Discovery

```http
GET /.well-known/openid-configuration
```

Returns standard OIDC provider metadata (issuer, endpoints, supported scopes, etc.).

### Registered Clients

| Client             | Client ID     | Auth Method         | Grant Type           | Scopes                    | PKCE     |
|--------------------|---------------|---------------------|----------------------|---------------------------|----------|
| **IAM Web** (SPA)  | `iam-web`     | none (public)       | authorization_code   | openid, email, profile    | Required |
| **IAM Service** (M2M) | `iam-service` | client_secret_basic | client_credentials | iam:read, iam:write       | N/A      |

### Authorization Code Flow with PKCE (for SPAs)

```
Your App                   IAM Auth Server              Google
   │                            │                         │
   ├── GET /oauth2/authorize ──>│                         │
   │   ?client_id=iam-web       │                         │
   │   &response_type=code      ├── redirect (if needed) ─>│
   │   &scope=openid email...   │                         │
   │   &redirect_uri=.../cb     │<── callback + code ──────┤
   │   &code_challenge=...      │                         │
   │   &code_challenge_method=S256                        │
   │                            │                         │
   │<── redirect ?code=xxx ─────┤                         │
   │                            │                         │
   ├── POST /oauth2/token ─────>│                         │
   │   (code + code_verifier)   │                         │
   │<── { access_token,         │                         │
   │      id_token,             │                         │
   │      refresh_token } ──────┤                         │
```

#### Step 1 — Generate PKCE

```typescript
async function generatePkce() {
  const verifier = crypto.randomUUID() + crypto.randomUUID()
  const encoder = new TextEncoder()
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(verifier))
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return { verifier, challenge }
}
```

#### Step 2 — Redirect to Authorize

```typescript
const { verifier, challenge } = await generatePkce()
sessionStorage.setItem('pkce_verifier', verifier)

const params = new URLSearchParams({
  client_id: 'iam-web',
  response_type: 'code',
  scope: 'openid email profile',
  redirect_uri: 'http://localhost:3000/callback',
  code_challenge: challenge,
  code_challenge_method: 'S256',
})

window.location.href = `http://localhost:8080/oauth2/authorize?${params}`
```

#### Step 3 — Exchange Code on Callback

```typescript
// pages/callback.vue
const route = useRoute()
const code = route.query.code as string
const verifier = sessionStorage.getItem('pkce_verifier')!

const body = new URLSearchParams({
  grant_type: 'authorization_code',
  client_id: 'iam-web',
  code,
  redirect_uri: 'http://localhost:3000/callback',
  code_verifier: verifier,
})

const res = await fetch('http://localhost:8080/oauth2/token', {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body,
})
const tokens = await res.json()
// tokens: { access_token, id_token, refresh_token, token_type, expires_in, scope }
```

### Client Credentials Flow (Machine-to-Machine)

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u iam-service:changeme \
  -d 'grant_type=client_credentials&scope=iam:read iam:write'
```

### Standard Endpoints

| Endpoint         | Path                                  |
|------------------|---------------------------------------|
| OIDC Discovery   | `GET /.well-known/openid-configuration` |
| Authorize        | `GET /oauth2/authorize`               |
| Token            | `POST /oauth2/token`                  |
| JWKS             | `GET /oauth2/jwks`                    |
| User Info        | `GET /oauth2/userinfo`                |
| Revoke           | `POST /oauth2/revoke`                 |
| Introspect       | `POST /oauth2/introspect`             |

### OIDC ID Token Custom Claims

The ID token includes these custom claims beyond the standard OIDC set:

```json
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "roles": ["USER"]
}
```

---

## 7. Error Codes Reference

| Code                          | HTTP | When                                          |
|-------------------------------|------|-----------------------------------------------|
| `BAD_REQUEST`                 | 400  | Malformed request / blank email on OTP send   |
| `UNAUTHORIZED`                | 401  | Missing or invalid JWT                        |
| `FORBIDDEN`                   | 403  | Insufficient permissions                      |
| `CONFLICT`                    | 409  | Duplicate resource                            |
| `VALIDATION_ERROR`            | 422  | Field validation failed                       |
| `RATE_LIMIT_EXCEEDED`         | 429  | Global rate limit hit                         |
| `INTERNAL_ERROR`              | 500  | Unexpected server error                       |
| `USER_NOT_FOUND`              | 404  | User ID does not exist                        |
| `USER_EMAIL_CONFLICT`         | 409  | Email already registered (internal conflict)  |
| `USER_DISABLED`               | 403  | Account is disabled                           |
| `EMAIL_ALREADY_REGISTERED`    | 409  | Self-registration: email already has an account — redirect to login |
| `GOOGLE_TOKEN_INVALID`        | 401  | Google ID token verification failed           |
| `PASSKEY_NOT_FOUND`           | 404  | Passkey credential not found                  |
| `PASSKEY_COUNTER_INVALID`     | 401  | Passkey counter mismatch (cloned key?)        |
| `PASSKEY_CHALLENGE_EXPIRED`   | 400  | WebAuthn challenge timed out                  |
| `PASSKEY_ATTESTATION_FAILED`  | 400  | WebAuthn attestation verification failed      |
| `OTP_INVALID`                 | 400  | Wrong OTP code                                |
| `OTP_EXPIRED`                 | 400  | OTP code expired (5-min TTL)                  |
| `OTP_MAX_ATTEMPTS`            | 429  | 3 wrong OTP attempts, must resend             |
| `OTP_SEND_LIMIT_EXCEEDED`     | 429  | 3 OTP sends in 10-min window                  |
| `TOKEN_INVALID`               | 401  | JWT malformed or signature invalid            |
| `TOKEN_EXPIRED`               | 401  | JWT expired — refresh it                      |
| `TOKEN_REVOKED`               | 401  | Refresh token was revoked — re-login          |

---

## 8. Complete Endpoint Reference

### Public Endpoints (No JWT)

| Method | Path                                            | Purpose                            |
|--------|-------------------------------------------------|------------------------------------|
| GET    | `/oauth2/authorization/google`                  | Initiate Google login (open in popup) |
| POST   | `/api/v1/auth/refresh`                          | Refresh access token               |
| POST   | `/api/v1/auth/logout`                           | Revoke refresh tokens              |
| POST   | `/api/v1/auth/passkey/authenticate/start`       | Get passkey challenge              |
| POST   | `/api/v1/auth/passkey/authenticate/finish`      | Verify passkey assertion, get tokens |
| POST   | `/api/v1/auth/register/send-otp`                | Send OTP to new email (check uniqueness + rate limit) |
| POST   | `/api/v1/auth/register/verify-otp`              | Verify OTP code, get `otpToken`    |
| POST   | `/api/v1/auth/register/passkey/start`           | Consume `otpToken`, create WebAuthn challenge |
| POST   | `/api/v1/auth/register/passkey/finish`          | Verify attestation, create user + passkey, get tokens |
| GET    | `/oauth2/authorize`                             | OAuth2 AS authorize endpoint       |
| POST   | `/oauth2/token`                                 | OAuth2 AS token endpoint           |
| GET    | `/.well-known/openid-configuration`             | OIDC discovery                     |
| GET    | `/oauth2/jwks`                                  | Public keys (JWKS)                 |
| GET    | `/actuator/health`                              | Health check                       |
| GET    | `/swagger-ui/**`                                | Swagger UI                         |
| GET    | `/v3/api-docs/**`                               | OpenAPI JSON                       |

### Authenticated Endpoints (JWT Required)

| Method | Path                                            | Purpose                           |
|--------|-------------------------------------------------|-----------------------------------|
| POST   | `/api/v1/auth/passkey/register/send-otp`        | Send OTP email for passkey registration |
| POST   | `/api/v1/auth/passkey/register/verify-otp`      | Verify OTP code                   |
| POST   | `/api/v1/auth/passkey/register/start`           | Start passkey registration        |
| POST   | `/api/v1/auth/passkey/register/finish`          | Finish passkey registration       |
| GET    | `/api/v1/auth/passkey/credentials`              | List user's passkeys              |
| DELETE | `/api/v1/auth/passkey/credentials/{id}`         | Delete a passkey                  |
| GET    | `/api/v1/users/{id}`                            | Get user by ID                    |
| POST   | `/api/v1/users`                                 | Create user                       |
| PATCH  | `/api/v1/users/{id}`                            | Update user display name          |
| PATCH  | `/api/v1/users/{id}/status`                     | Change user status                |
| DELETE | `/api/v1/users/{id}`                            | Delete user                       |
| GET    | `/api/v1/audit-logs`                            | Query audit logs (paginated)      |

---

## 9. JWT Access Token Claims

Decode with any JWT library (e.g. `jose` npm package). Do **not** verify signature on the frontend — let the backend handle that.

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "roles": ["USER"],
  "iat": 1709538600,
  "exp": 1709539500
}
```

- Use `sub` as the user ID for API calls
- Use `exp` to know when to proactively refresh

---

## 10. Utility Functions

```javascript
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

## 11. Environment Checklist

Variables the frontend team needs from the backend team:

| Variable           | Example                                | Used For                           |
|--------------------|----------------------------------------|------------------------------------|
| `BACKEND_URL`      | `http://localhost:8080`                | All API calls                      |
| `GOOGLE_CLIENT_ID` | `xxx.apps.googleusercontent.com`       | Only if using WebAuthn JS directly |
| Redirect URI       | `http://localhost:3000/callback`       | OAuth2 AS authorization code flow  |

Ensure the backend `CORS_ALLOWED_ORIGINS` includes your frontend origin.
