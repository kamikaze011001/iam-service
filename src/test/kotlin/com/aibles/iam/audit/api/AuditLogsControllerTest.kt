package com.aibles.iam.audit.api

import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.audit.usecase.RecordAuditEventUseCase
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.identity.usecase.ChangeUserStatusUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.identity.usecase.DeleteUserUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.identity.usecase.UpdateUserUseCase
import com.aibles.iam.shared.error.GlobalExceptionHandler
import com.aibles.iam.shared.pagination.PageResponse
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.time.Instant
import java.util.UUID

@WebMvcTest
@Import(GlobalExceptionHandler::class, AuditLogsController::class)
@AutoConfigureMockMvc(addFilters = false)
class AuditLogsControllerTest {

    @Autowired lateinit var mockMvc: MockMvc
    @MockkBean lateinit var queryAuditLogsUseCase: QueryAuditLogsUseCase

    // RecordAuditEventUseCase is a @Component with @EventListener — must be mocked
    @MockkBean lateinit var recordAuditEventUseCase: RecordAuditEventUseCase

    // UsersController deps
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase

    // AuthController deps
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase

    // PasskeyController deps
    @MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
    @MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
    @MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
    @MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
    @MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase
    @MockkBean lateinit var passkeyCredentialRepository: PasskeyCredentialRepository

    @Test
    fun `GET audit-logs returns paginated response`() {
        val logId = UUID.randomUUID()
        val userId = UUID.randomUUID()
        val now = Instant.now()

        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = listOf(
                QueryAuditLogsUseCase.AuditLogItem(
                    id = logId,
                    eventType = AuditEvent.USER_CREATED,
                    userId = userId,
                    actorId = null,
                    ipAddress = "10.0.0.1",
                    userAgent = "TestAgent",
                    metadata = null,
                    createdAt = now,
                )
            ),
            page = 0,
            size = 20,
            totalElements = 1,
            totalPages = 1,
        )

        mockMvc.get("/api/v1/audit-logs")
            .andExpect {
                status { isOk() }
                jsonPath("$.success") { value(true) }
                jsonPath("$.data.content[0].eventType") { value("USER_CREATED") }
                jsonPath("$.data.content[0].ipAddress") { value("10.0.0.1") }
                jsonPath("$.data.totalElements") { value(1) }
                jsonPath("$.data.page") { value(0) }
            }
    }

    @Test
    fun `GET audit-logs with filters passes params`() {
        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = emptyList(),
            page = 0,
            size = 10,
            totalElements = 0,
            totalPages = 0,
        )

        mockMvc.get("/api/v1/audit-logs") {
            param("eventType", "LOGIN_GOOGLE_SUCCESS")
            param("page", "0")
            param("size", "10")
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.content") { isEmpty() }
        }
    }

    @Test
    fun `GET audit-logs returns metadata as nested JSON object`() {
        val logId = UUID.randomUUID()
        val now = Instant.now()

        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = listOf(
                QueryAuditLogsUseCase.AuditLogItem(
                    id = logId,
                    eventType = AuditEvent.USER_CREATED,
                    userId = null,
                    actorId = null,
                    ipAddress = null,
                    userAgent = null,
                    metadata = """{"email":"a@b.com"}""",
                    createdAt = now,
                )
            ),
            page = 0,
            size = 20,
            totalElements = 1,
            totalPages = 1,
        )

        mockMvc.get("/api/v1/audit-logs")
            .andExpect {
                status { isOk() }
                jsonPath("$.data.content[0].metadata.email") { value("a@b.com") }
            }
    }

    @Test
    fun `GET audit-logs returns empty page when no logs`() {
        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = emptyList(),
            page = 0,
            size = 20,
            totalElements = 0,
            totalPages = 0,
        )

        mockMvc.get("/api/v1/audit-logs")
            .andExpect {
                status { isOk() }
                jsonPath("$.success") { value(true) }
                jsonPath("$.data.totalElements") { value(0) }
            }
    }
}
