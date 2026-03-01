package com.aibles.iam.authentication.api

import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.audit.usecase.RecordAuditEventUseCase
import com.aibles.iam.authentication.domain.passkey.PasskeyCredential
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
import com.aibles.iam.shared.error.ErrorCode
import com.aibles.iam.shared.error.GlobalExceptionHandler
import com.aibles.iam.shared.error.NotFoundException
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import io.mockk.justRun
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
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
    @MockkBean lateinit var credentialRepository: PasskeyCredentialRepository
    @MockkBean lateinit var getUserUseCase: GetUserUseCase

    // AuthController deps (scanned by @WebMvcTest)
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase

    // UsersController deps (scanned by @WebMvcTest)
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase

    // AuditLogsController deps (scanned by @WebMvcTest — must be mocked)
    @MockkBean lateinit var queryAuditLogsUseCase: QueryAuditLogsUseCase
    @MockkBean lateinit var recordAuditEventUseCase: RecordAuditEventUseCase

    private val userId = UUID.randomUUID()

    @BeforeEach
    fun setUpSecurityContext() {
        val jwt = Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject(userId.toString())
            .build()
        val context = SecurityContextHolder.createEmptyContext()
        context.authentication = JwtAuthenticationToken(jwt)
        SecurityContextHolder.setContext(context)
    }

    @AfterEach
    fun clearSecurityContext() {
        SecurityContextHolder.clearContext()
    }

    @Test
    fun `POST register-start returns 200 with sessionId and options`() {
        every { getUserUseCase.execute(GetUserUseCase.Query(userId)) } returns
            com.aibles.iam.identity.domain.user.User.create("user@test.com", "Test User")
        every { registerPasskeyStartUseCase.execute(any()) } returns
            RegisterPasskeyStartUseCase.Result(
                sessionId = "sess-1", rpId = "localhost", rpName = "Test",
                userId = userId.toString(), userEmail = "user@test.com", userDisplayName = null,
                challenge = "Y2hhbGxlbmdl",
            )

        mockMvc.post("/api/v1/auth/passkey/register/start") {
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
        every { credentialRepository.findAllByUserId(userId) } returns emptyList()

        mockMvc.get("/api/v1/auth/passkey/credentials") {
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data") { isArray() }
        }
    }

    @Test
    fun `DELETE credentials-{id} not found returns 404`() {
        val credId = UUID.randomUUID()
        every { deletePasskeyUseCase.execute(DeletePasskeyUseCase.Command(userId, credId)) } throws
            NotFoundException("Not found", ErrorCode.PASSKEY_NOT_FOUND)

        mockMvc.delete("/api/v1/auth/passkey/credentials/$credId") {
        }.andExpect {
            status { isNotFound() }
            jsonPath("$.error.code") { value("PASSKEY_NOT_FOUND") }
        }
    }
}
