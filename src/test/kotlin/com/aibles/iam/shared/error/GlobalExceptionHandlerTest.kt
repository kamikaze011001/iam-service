package com.aibles.iam.shared.error

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
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import com.ninjasquad.springmockk.MockkBean
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import jakarta.validation.Valid
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank

@WebMvcTest
@Import(GlobalExceptionHandler::class, GlobalExceptionHandlerTest.TestController::class)
@org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc(addFilters = false)
class GlobalExceptionHandlerTest {

    @Autowired lateinit var mockMvc: MockMvc
    @Autowired lateinit var objectMapper: ObjectMapper
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase

    // AuthController deps (scanned by @WebMvcTest — must be mocked)
    @MockkBean lateinit var refreshTokenUseCase: RefreshTokenUseCase
    @MockkBean lateinit var revokeTokenUseCase: RevokeTokenUseCase

    // PasskeyController deps (scanned by @WebMvcTest — must be mocked)
    @MockkBean lateinit var registerPasskeyStartUseCase: RegisterPasskeyStartUseCase
    @MockkBean lateinit var registerPasskeyFinishUseCase: RegisterPasskeyFinishUseCase
    @MockkBean lateinit var authenticatePasskeyStartUseCase: AuthenticatePasskeyStartUseCase
    @MockkBean lateinit var authenticatePasskeyFinishUseCase: AuthenticatePasskeyFinishUseCase
    @MockkBean lateinit var deletePasskeyUseCase: DeletePasskeyUseCase
    @MockkBean lateinit var passkeyCredentialRepository: PasskeyCredentialRepository

    @RestController
    class TestController {
        @GetMapping("/test/not-found")
        fun notFound(): Nothing = throw NotFoundException("User not found", ErrorCode.USER_NOT_FOUND)

        @GetMapping("/test/conflict")
        fun conflict(): Nothing = throw ConflictException("Email taken", ErrorCode.USER_EMAIL_CONFLICT)

        @GetMapping("/test/unauthorized")
        fun unauthorized(): Nothing = throw UnauthorizedException("Bad token", ErrorCode.TOKEN_INVALID)

        @GetMapping("/test/forbidden")
        fun forbidden(): Nothing = throw ForbiddenException("Disabled", ErrorCode.USER_DISABLED)

        @GetMapping("/test/unexpected")
        fun unexpected(): Nothing = throw RuntimeException("Boom")

        @PostMapping("/test/validation")
        fun validation(@Valid @RequestBody body: TestRequest): String = body.email

        data class TestRequest(
            @field:NotBlank @field:Email val email: String = "",
        )
    }

    @Test
    fun `NotFoundException returns 404 with USER_NOT_FOUND code`() {
        mockMvc.get("/test/not-found")
            .andExpect {
                status { isNotFound() }
                jsonPath("$.success") { value(false) }
                jsonPath("$.error.code") { value("USER_NOT_FOUND") }
                jsonPath("$.data") { doesNotExist() }
                jsonPath("$.timestamp") { exists() }
            }
    }

    @Test
    fun `ConflictException returns 409 with USER_EMAIL_CONFLICT code`() {
        mockMvc.get("/test/conflict")
            .andExpect {
                status { isConflict() }
                jsonPath("$.error.code") { value("USER_EMAIL_CONFLICT") }
            }
    }

    @Test
    fun `UnauthorizedException returns 401 with TOKEN_INVALID code`() {
        mockMvc.get("/test/unauthorized")
            .andExpect {
                status { isUnauthorized() }
                jsonPath("$.error.code") { value("TOKEN_INVALID") }
            }
    }

    @Test
    fun `ForbiddenException returns 403 with USER_DISABLED code`() {
        mockMvc.get("/test/forbidden")
            .andExpect {
                status { isForbidden() }
                jsonPath("$.error.code") { value("USER_DISABLED") }
            }
    }

    @Test
    fun `unexpected Exception returns 500 with INTERNAL_ERROR code`() {
        mockMvc.get("/test/unexpected")
            .andExpect {
                status { isInternalServerError() }
                jsonPath("$.error.code") { value("INTERNAL_ERROR") }
                jsonPath("$.success") { value(false) }
            }
    }

    @Test
    fun `validation failure returns 422 with VALIDATION_ERROR code`() {
        mockMvc.post("/test/validation") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"email": "not-an-email"}"""
        }.andExpect {
            status { isUnprocessableEntity() }
            jsonPath("$.error.code") { value("VALIDATION_ERROR") }
            jsonPath("$.success") { value(false) }
        }
    }

    @Test
    fun `success response shape has success=true and null error`() {
        val response = ApiResponse.ok("data")
        assert(response.success)
        assert(response.error == null)
        assert(response.data == "data")
    }
}
