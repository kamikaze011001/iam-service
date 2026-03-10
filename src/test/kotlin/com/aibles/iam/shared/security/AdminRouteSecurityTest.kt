package com.aibles.iam.shared.security

import com.aibles.iam.audit.usecase.QueryAuditLogsUseCase
import com.aibles.iam.audit.usecase.RecordAuditEventUseCase
import com.aibles.iam.authentication.domain.passkey.PasskeyCredentialRepository
import com.aibles.iam.authentication.infra.GoogleOAuth2FailureHandler
import com.aibles.iam.authentication.infra.GoogleOAuth2SuccessHandler
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.AuthenticatePasskeyStartUseCase
import com.aibles.iam.authentication.usecase.DeletePasskeyUseCase
import com.aibles.iam.authentication.usecase.FinishRegistrationUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyFinishUseCase
import com.aibles.iam.authentication.usecase.RegisterPasskeyStartUseCase
import com.aibles.iam.authentication.usecase.SendPasskeyOtpUseCase
import com.aibles.iam.authentication.usecase.SendRegistrationOtpUseCase
import com.aibles.iam.authentication.usecase.StartRegistrationUseCase
import com.aibles.iam.authentication.usecase.VerifyPasskeyOtpUseCase
import com.aibles.iam.authentication.usecase.VerifyRegistrationOtpUseCase
import com.aibles.iam.authorization.usecase.RefreshTokenUseCase
import com.aibles.iam.authorization.usecase.RevokeTokenUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.identity.usecase.ChangeUserStatusUseCase
import com.aibles.iam.identity.usecase.CreateUserUseCase
import com.aibles.iam.identity.usecase.DeleteUserUseCase
import com.aibles.iam.identity.usecase.GetUserUseCase
import com.aibles.iam.identity.usecase.UpdateUserUseCase
import com.aibles.iam.shared.config.SecurityConfig
import com.aibles.iam.shared.error.GlobalExceptionHandler
import com.aibles.iam.shared.pagination.PageResponse
import com.aibles.iam.shared.web.HttpContextExtractor
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Import
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.context.TestPropertySource
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import java.util.UUID

@WebMvcTest
@Import(SecurityConfig::class, GlobalExceptionHandler::class)
@TestPropertySource(properties = [
    "cors.allowed-origins=http://localhost:3000",
    "cors.allowed-methods=GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "cors.allowed-headers=*",
    "cors.max-age=3600",
])
class AdminRouteSecurityTest {

    @Autowired lateinit var mockMvc: MockMvc

    // SecurityConfig constructor deps
    @MockkBean lateinit var googleOAuth2SuccessHandler: GoogleOAuth2SuccessHandler
    @MockkBean lateinit var googleOAuth2FailureHandler: GoogleOAuth2FailureHandler
    @MockkBean lateinit var jwtDecoder: JwtDecoder

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
    @MockkBean lateinit var sendPasskeyOtpUseCase: SendPasskeyOtpUseCase
    @MockkBean lateinit var verifyPasskeyOtpUseCase: VerifyPasskeyOtpUseCase

    // RegisterController deps
    @MockkBean lateinit var sendRegistrationOtpUseCase: SendRegistrationOtpUseCase
    @MockkBean lateinit var verifyRegistrationOtpUseCase: VerifyRegistrationOtpUseCase
    @MockkBean lateinit var startRegistrationUseCase: StartRegistrationUseCase
    @MockkBean lateinit var finishRegistrationUseCase: FinishRegistrationUseCase

    // AuditLogsController deps
    @MockkBean lateinit var queryAuditLogsUseCase: QueryAuditLogsUseCase
    @MockkBean lateinit var recordAuditEventUseCase: RecordAuditEventUseCase

    // Shared deps used by PasskeyController and RegisterController
    @MockkBean lateinit var applicationEventPublisher: ApplicationEventPublisher
    @MockkBean lateinit var httpContextExtractor: HttpContextExtractor

    private val testUser = User.create("admin@example.com", "Admin")

    @Test
    fun `ROLE_USER cannot GET users - receives 403`() {
        mockMvc.get("/api/v1/users/${UUID.randomUUID()}") {
            with(jwt().authorities(SimpleGrantedAuthority("ROLE_USER")))
        }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `ROLE_ADMIN can GET users`() {
        every { getUserUseCase.execute(any()) } returns testUser
        mockMvc.get("/api/v1/users/${testUser.id}") {
            with(jwt().authorities(SimpleGrantedAuthority("ROLE_ADMIN")))
        }.andExpect { status { isOk() } }
    }

    @Test
    fun `unauthenticated request to admin route receives 401`() {
        mockMvc.get("/api/v1/users/${UUID.randomUUID()}")
            .andExpect { status { isUnauthorized() } }
    }

    @Test
    fun `ROLE_USER cannot GET audit-logs - receives 403`() {
        mockMvc.get("/api/v1/audit-logs") {
            with(jwt().authorities(SimpleGrantedAuthority("ROLE_USER")))
        }.andExpect { status { isForbidden() } }
    }

    @Test
    fun `ROLE_ADMIN can GET audit-logs`() {
        every { queryAuditLogsUseCase.execute(any()) } returns PageResponse(
            content = emptyList(), page = 0, size = 20, totalElements = 0L, totalPages = 0
        )
        mockMvc.get("/api/v1/audit-logs") {
            with(jwt().authorities(SimpleGrantedAuthority("ROLE_ADMIN")))
        }.andExpect { status { isOk() } }
    }
}
