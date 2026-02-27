package com.aibles.iam.authentication.api

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
import com.aibles.iam.shared.error.UnauthorizedException
import com.ninjasquad.springmockk.MockkBean
import io.mockk.every
import io.mockk.justRun
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

@WebMvcTest
@Import(GlobalExceptionHandler::class, AuthController::class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired lateinit var mockMvc: MockMvc

    // AuthController deps
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase

    // UsersController deps (scanned by @WebMvcTest — must be mocked)
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase

    // PasskeyController deps (scanned by @WebMvcTest — must be mocked)
    @MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
    @MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
    @MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
    @MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
    @MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase
    @MockkBean lateinit var passkeyCredentialRepository: PasskeyCredentialRepository

    @Test
    fun `POST refresh returns 200 with new token pair`() {
        every { refreshTokenUseCase.execute(any()) } returns
            RefreshTokenUseCase.Result("new-access", "new-refresh", 900)

        mockMvc.post("/api/v1/auth/refresh") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"refreshToken":"old-token"}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.accessToken") { value("new-access") }
            jsonPath("$.data.refreshToken") { value("new-refresh") }
            jsonPath("$.data.expiresIn") { value(900) }
        }
    }

    @Test
    fun `POST refresh with invalid token returns 401 with TOKEN_INVALID`() {
        every { refreshTokenUseCase.execute(any()) } throws
            UnauthorizedException("Token invalid", ErrorCode.TOKEN_INVALID)

        mockMvc.post("/api/v1/auth/refresh") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"refreshToken":"bad-token"}"""
        }.andExpect {
            status { isUnauthorized() }
            jsonPath("$.success") { value(false) }
            jsonPath("$.error.code") { value("TOKEN_INVALID") }
        }
    }

    @Test
    fun `POST logout returns 204 No Content`() {
        justRun { revokeTokenUseCase.execute(any()) }

        mockMvc.post("/api/v1/auth/logout") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"refreshToken":"some-token"}"""
        }.andExpect {
            status { isNoContent() }
        }

        verify(exactly = 1) { revokeTokenUseCase.execute(RevokeTokenUseCase.Command("some-token")) }
    }
}
