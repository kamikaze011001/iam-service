# Admin Account Management Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable admin account creation via environment-variable bootstrap at startup, and allow existing admins to update any user's roles via `PUT /api/v1/users/{id}/roles`.

**Architecture:** Two pieces. (1) `AdminBootstrapRunner` (`ApplicationRunner`) reads `BOOTSTRAP_ADMIN_EMAIL` at every startup — if the user exists and lacks `ADMIN`, it promotes them idempotently. (2) `UpdateUserRolesUseCase` replaces a user's full role set; `UsersController` exposes it at `PUT /api/v1/users/{id}/roles` which is already protected to `ROLE_ADMIN` by the URL rule in `SecurityConfig`. The `User` entity gets a `updateRoles()` domain method to keep business logic in the entity.

**Tech Stack:** Spring Boot 3.4.x, Kotlin 2.x, Spring Data JPA, MockK, `spring-security-test` (`jwt()` post-processor).

---

### Task 1: `AdminBootstrapRunner` — promote first admin from env var

**Context:**
On every app startup, check `app.bootstrap.admin-email`. If set, find the user and grant `ADMIN` role if they don't already have it. This is idempotent and safe to run on every restart. The user must already exist (registered via Google or passkey) — the runner does not create users.

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/identity/infra/AdminBootstrapRunner.kt`
- Create: `src/test/kotlin/com/aibles/iam/identity/infra/AdminBootstrapRunnerTest.kt`
- Modify: `.env.example` (add the new property)

**Step 1: Write the failing tests**

```kotlin
// src/test/kotlin/com/aibles/iam/identity/infra/AdminBootstrapRunnerTest.kt
package com.aibles.iam.identity.infra

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.test.util.ReflectionTestUtils
import org.springframework.boot.ApplicationArguments

class AdminBootstrapRunnerTest {

    private val userRepository = mockk<UserRepository>()
    private val runner = AdminBootstrapRunner(userRepository)
    private val args = mockk<ApplicationArguments>(relaxed = true)

    private fun setEmail(email: String) =
        ReflectionTestUtils.setField(runner, "adminEmail", email)

    @Test
    fun `does nothing when adminEmail is blank`() {
        setEmail("")
        runner.run(args)
        verify(exactly = 0) { userRepository.findByEmail(any()) }
    }

    @Test
    fun `does nothing when user is not found`() {
        setEmail("admin@example.com")
        every { userRepository.findByEmail("admin@example.com") } returns null
        runner.run(args)
        verify(exactly = 0) { userRepository.save(any()) }
    }

    @Test
    fun `does nothing when user already has ADMIN role`() {
        setEmail("admin@example.com")
        val user = User.create("admin@example.com").apply { roles.add("ADMIN") }
        every { userRepository.findByEmail("admin@example.com") } returns user
        runner.run(args)
        verify(exactly = 0) { userRepository.save(any()) }
    }

    @Test
    fun `promotes user to ADMIN when user exists without ADMIN role`() {
        setEmail("admin@example.com")
        val user = User.create("admin@example.com")
        every { userRepository.findByEmail("admin@example.com") } returns user
        every { userRepository.save(user) } returns user
        runner.run(args)
        assertThat(user.roles).contains("ADMIN")
        verify { userRepository.save(user) }
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
./gradlew test --tests "com.aibles.iam.identity.infra.AdminBootstrapRunnerTest" -x jacocoTestReport
```
Expected: FAIL — `AdminBootstrapRunner` does not exist yet.

**Step 3: Create `AdminBootstrapRunner.kt`**

```kotlin
// src/main/kotlin/com/aibles/iam/identity/infra/AdminBootstrapRunner.kt
package com.aibles.iam.identity.infra

import com.aibles.iam.identity.domain.user.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.stereotype.Component

@Component
class AdminBootstrapRunner(
    private val userRepository: UserRepository,
) : ApplicationRunner {

    private val logger = LoggerFactory.getLogger(javaClass)

    @Value("\${app.bootstrap.admin-email:}")
    private lateinit var adminEmail: String

    override fun run(args: ApplicationArguments) {
        if (adminEmail.isBlank()) return

        val user = userRepository.findByEmail(adminEmail)
        if (user == null) {
            logger.warn("Bootstrap: admin user '{}' not found — register them first", adminEmail)
            return
        }
        if (user.roles.contains("ADMIN")) {
            logger.info("Bootstrap: '{}' already has ADMIN role", adminEmail)
            return
        }
        user.roles.add("ADMIN")
        userRepository.save(user)
        logger.info("Bootstrap: promoted '{}' to ADMIN", adminEmail)
    }
}
```

**Step 4: Add property to `.env.example`**

Add this line to `.env.example`:
```
# Email of the user to promote to ADMIN on startup (optional; user must already be registered)
BOOTSTRAP_ADMIN_EMAIL=
```

And add to `src/main/resources/application.properties` (or confirm it already has a Spring property binding):
```properties
app.bootstrap.admin-email=${BOOTSTRAP_ADMIN_EMAIL:}
```

**Step 5: Run tests to verify they pass**

```bash
./gradlew test --tests "com.aibles.iam.identity.infra.AdminBootstrapRunnerTest" -x jacocoTestReport
```
Expected: all 4 tests PASS.

**Step 6: Run all tests**

```bash
./gradlew test -x jacocoTestReport
```
Expected: all pass.

**Step 7: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/identity/infra/AdminBootstrapRunner.kt \
        src/test/kotlin/com/aibles/iam/identity/infra/AdminBootstrapRunnerTest.kt \
        .env.example \
        src/main/resources/application.properties
git commit -m "feat: bootstrap first admin from BOOTSTRAP_ADMIN_EMAIL env var at startup"
```

---

### Task 2: `UpdateUserRolesUseCase` + domain method + enum/error entries

**Context:**
Add the domain method `User.updateRoles()`, a new `AuditEvent.USER_ROLES_UPDATED`, a new `ErrorCode.INVALID_ROLE`, and the use case that validates + applies the role change.

Valid roles are `"USER"` and `"ADMIN"` — any other value is rejected with `INVALID_ROLE`.

**Files:**
- Modify: `src/main/kotlin/com/aibles/iam/identity/domain/user/User.kt`
- Modify: `src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt`
- Modify: `src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt`
- Create: `src/main/kotlin/com/aibles/iam/identity/usecase/UpdateUserRolesUseCase.kt`
- Create: `src/test/kotlin/com/aibles/iam/identity/usecase/UpdateUserRolesUseCaseTest.kt`

**Step 1: Write the failing tests**

```kotlin
// src/test/kotlin/com/aibles/iam/identity/usecase/UpdateUserRolesUseCaseTest.kt
package com.aibles.iam.identity.usecase

import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.web.HttpContextExtractor
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.context.ApplicationEventPublisher
import java.util.Optional
import java.util.UUID

class UpdateUserRolesUseCaseTest {

    private val userRepository = mockk<UserRepository>()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val httpContextExtractor = mockk<HttpContextExtractor> {
        every { clientIp() } returns "127.0.0.1"
        every { userAgent() } returns "test-agent"
    }
    private val useCase = UpdateUserRolesUseCase(userRepository, eventPublisher, httpContextExtractor)

    private val actorId = UUID.randomUUID()
    private val targetUser = User.create("target@example.com")

    @Test
    fun `replaces roles and returns updated user`() {
        every { userRepository.findById(targetUser.id) } returns Optional.of(targetUser)
        every { userRepository.save(targetUser) } returns targetUser

        val result = useCase.execute(
            UpdateUserRolesUseCase.Command(actorId, targetUser.id, setOf("USER", "ADMIN"))
        )

        assertThat(result.user.roles).containsExactlyInAnyOrder("USER", "ADMIN")
        verify { userRepository.save(targetUser) }
    }

    @Test
    fun `throws INVALID_ROLE for unknown role value`() {
        val ex = assertThrows<BadRequestException> {
            useCase.execute(
                UpdateUserRolesUseCase.Command(actorId, targetUser.id, setOf("USER", "SUPERUSER"))
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.INVALID_ROLE)
    }

    @Test
    fun `throws INVALID_ROLE for empty roles set`() {
        val ex = assertThrows<BadRequestException> {
            useCase.execute(
                UpdateUserRolesUseCase.Command(actorId, targetUser.id, emptySet())
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.INVALID_ROLE)
    }

    @Test
    fun `throws USER_NOT_FOUND when user does not exist`() {
        val missingId = UUID.randomUUID()
        every { userRepository.findById(missingId) } returns Optional.empty()

        val ex = assertThrows<NotFoundException> {
            useCase.execute(
                UpdateUserRolesUseCase.Command(actorId, missingId, setOf("ADMIN"))
            )
        }
        assertThat(ex.errorCode).isEqualTo(ErrorCode.USER_NOT_FOUND)
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
./gradlew test --tests "com.aibles.iam.identity.usecase.UpdateUserRolesUseCaseTest" -x jacocoTestReport
```
Expected: FAIL — `UpdateUserRolesUseCase`, `ErrorCode.INVALID_ROLE`, `AuditEvent.USER_ROLES_UPDATED` don't exist yet.

**Step 3: Add `updateRoles()` to `User.kt`**

Add this method to the `User` class body (alongside `updateProfile`, `disable`, `enable`, etc.):

```kotlin
fun updateRoles(newRoles: Set<String>) {
    roles.clear()
    roles.addAll(newRoles)
    updatedAt = Instant.now()
}
```

**Step 4: Add `USER_ROLES_UPDATED` to `AuditEvent.kt`**

```kotlin
// Add to the enum after REGISTRATION_COMPLETED:
USER_ROLES_UPDATED,
```

**Step 5: Add `INVALID_ROLE` to `ErrorCode.kt`**

```kotlin
// Add after USER_DISABLED:
INVALID_ROLE(HttpStatus.BAD_REQUEST),
```

**Step 6: Create `UpdateUserRolesUseCase.kt`**

```kotlin
// src/main/kotlin/com/aibles/iam/identity/usecase/UpdateUserRolesUseCase.kt
package com.aibles.iam.identity.usecase

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.domain.user.UserRepository
import com.aibles.iam.shared.error.BadRequestException
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.NotFoundException
import com.aibles.iam.shared.web.HttpContextExtractor
import org.springframework.context.ApplicationEventPublisher
import org.springframework.stereotype.Component
import java.util.UUID

@Component
class UpdateUserRolesUseCase(
    private val userRepository: UserRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val httpContextExtractor: HttpContextExtractor,
) {
    companion object {
        private val VALID_ROLES = setOf("USER", "ADMIN")
    }

    data class Command(val actorId: UUID, val targetUserId: UUID, val roles: Set<String>)
    data class Result(val user: User)

    fun execute(command: Command): Result {
        if (command.roles.isEmpty()) {
            throw BadRequestException("Roles cannot be empty", ErrorCode.INVALID_ROLE)
        }
        val invalidRoles = command.roles.filterNot { it in VALID_ROLES }
        if (invalidRoles.isNotEmpty()) {
            throw BadRequestException("Invalid roles: $invalidRoles", ErrorCode.INVALID_ROLE)
        }
        val user = userRepository.findById(command.targetUserId)
            .orElseThrow { NotFoundException("User not found", ErrorCode.USER_NOT_FOUND) }
        user.updateRoles(command.roles)
        val saved = userRepository.save(user)
        eventPublisher.publishEvent(
            AuditDomainEvent(
                eventType = AuditEvent.USER_ROLES_UPDATED,
                userId = command.targetUserId,
                actorId = command.actorId,
                ipAddress = httpContextExtractor.clientIp(),
                userAgent = httpContextExtractor.userAgent(),
                metadata = mapOf("roles" to command.roles.sorted().joinToString(",")),
            )
        )
        return Result(saved)
    }
}
```

**Step 7: Run tests to verify they pass**

```bash
./gradlew test --tests "com.aibles.iam.identity.usecase.UpdateUserRolesUseCaseTest" -x jacocoTestReport
```
Expected: all 4 tests PASS.

**Step 8: Run all tests**

```bash
./gradlew test -x jacocoTestReport
```
Expected: all pass.

**Step 9: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/identity/domain/user/User.kt \
        src/main/kotlin/com/aibles/iam/audit/domain/log/AuditEvent.kt \
        src/main/kotlin/com/aibles/iam/shared/error/ErrorCode.kt \
        src/main/kotlin/com/aibles/iam/identity/usecase/UpdateUserRolesUseCase.kt \
        src/test/kotlin/com/aibles/iam/identity/usecase/UpdateUserRolesUseCaseTest.kt
git commit -m "feat: add UpdateUserRolesUseCase with INVALID_ROLE error and USER_ROLES_UPDATED audit event"
```

---

### Task 3: `PUT /api/v1/users/{id}/roles` controller endpoint

**Context:**
Expose `UpdateUserRolesUseCase` via `PUT /api/v1/users/{id}/roles`. The URL is already protected to `ROLE_ADMIN` by the `SecurityConfig` rule (`/api/v1/users/**` → `hasRole("ADMIN")`). The acting admin's UUID comes from the JWT `sub` claim via `@AuthenticationPrincipal`.

The existing `UsersControllerTest` uses `addFilters = false` (no security rules). We still need to set a JWT principal for the new endpoint — use `SecurityMockMvcRequestPostProcessors.jwt()` which works even with `addFilters = false` by setting the `SecurityContext` directly.

**Files:**
- Create: `src/main/kotlin/com/aibles/iam/identity/api/dto/UpdateUserRolesRequest.kt`
- Modify: `src/main/kotlin/com/aibles/iam/identity/api/UsersController.kt`
- Modify: `src/test/kotlin/com/aibles/iam/identity/api/UsersControllerTest.kt`

**Step 1: Write the failing test**

Add to `UsersControllerTest.kt`:

1. Add `@MockkBean` field (alongside the existing ones):
```kotlin
@MockkBean lateinit var updateUserRolesUseCase: UpdateUserRolesUseCase
```

2. Add the import at the top of the test file:
```kotlin
import com.aibles.iam.identity.usecase.UpdateUserRolesUseCase
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.put
```

3. Add the test method:
```kotlin
@Test
fun `PUT users-{id}-roles updates roles and returns user`() {
    val adminId = UUID.randomUUID()
    every { updateUserRolesUseCase.execute(any()) } returns UpdateUserRolesUseCase.Result(testUser)

    mockMvc.put("/api/v1/users/${testUser.id}/roles") {
        with(jwt().jwt { it.subject(adminId.toString()) })
        contentType = MediaType.APPLICATION_JSON
        content = """{"roles":["USER","ADMIN"]}"""
    }.andExpect {
        status { isOk() }
        jsonPath("$.success") { value(true) }
    }
}
```

**Step 2: Run test to verify it fails**

```bash
./gradlew test --tests "com.aibles.iam.identity.api.UsersControllerTest.PUT users*" -x jacocoTestReport
```
Expected: FAIL — endpoint doesn't exist yet (404).

**Step 3: Create `UpdateUserRolesRequest.kt`**

```kotlin
// src/main/kotlin/com/aibles/iam/identity/api/dto/UpdateUserRolesRequest.kt
package com.aibles.iam.identity.api.dto

import jakarta.validation.constraints.NotEmpty

data class UpdateUserRolesRequest(
    @field:NotEmpty(message = "Roles must not be empty")
    val roles: Set<String>,
)
```

**Step 4: Update `UsersController.kt`**

1. Add `updateUserRolesUseCase: UpdateUserRolesUseCase` to the constructor:
```kotlin
@RestController
@RequestMapping("/api/v1/users")
class UsersController(
    private val getUserUseCase: GetUserUseCase,
    private val createUserUseCase: CreateUserUseCase,
    private val updateUserUseCase: UpdateUserUseCase,
    private val changeUserStatusUseCase: ChangeUserStatusUseCase,
    private val deleteUserUseCase: DeleteUserUseCase,
    private val updateUserRolesUseCase: UpdateUserRolesUseCase,  // ← ADD
)
```

2. Add new imports:
```kotlin
import com.aibles.iam.identity.api.dto.UpdateUserRolesRequest
import com.aibles.iam.identity.usecase.UpdateUserRolesUseCase
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.web.bind.annotation.PutMapping
```

3. Add the endpoint method inside the class:
```kotlin
@PutMapping("/{id}/roles")
fun updateUserRoles(
    @PathVariable id: UUID,
    @AuthenticationPrincipal principal: Jwt,
    @Valid @RequestBody request: UpdateUserRolesRequest,
): ApiResponse<UserResponse> {
    val actorId = UUID.fromString(principal.subject)
    val result = updateUserRolesUseCase.execute(
        UpdateUserRolesUseCase.Command(
            actorId = actorId,
            targetUserId = id,
            roles = request.roles,
        )
    )
    return ApiResponse.ok(UserResponse.from(result.user))
}
```

**Step 5: Run test to verify it passes**

```bash
./gradlew test --tests "com.aibles.iam.identity.api.UsersControllerTest" -x jacocoTestReport
```
Expected: all tests PASS including the new one.

**Step 6: Run all tests**

```bash
./gradlew test -x jacocoTestReport
```
Expected: all pass.

**Step 7: Commit**

```bash
git add src/main/kotlin/com/aibles/iam/identity/api/dto/UpdateUserRolesRequest.kt \
        src/main/kotlin/com/aibles/iam/identity/api/UsersController.kt \
        src/test/kotlin/com/aibles/iam/identity/api/UsersControllerTest.kt
git commit -m "feat: add PUT /api/v1/users/{id}/roles endpoint for admin role management"
```

---

## Usage after merge

**Bootstrap first admin (env var):**
```bash
# In .env or Kubernetes secret:
BOOTSTRAP_ADMIN_EMAIL=admin@company.com
# Restart the service — user gets ADMIN on next startup
```

**Promote via API (admin promotes admin):**
```http
PUT /api/v1/users/{userId}/roles
Authorization: Bearer <admin-jwt>
Content-Type: application/json

{"roles": ["USER", "ADMIN"]}
```

**Demote an admin:**
```http
PUT /api/v1/users/{userId}/roles
{"roles": ["USER"]}
```
