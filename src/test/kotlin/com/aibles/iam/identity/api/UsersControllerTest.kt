package com.aibles.iam.identity.api

import com.aibles.iam.identity.domain.user.User
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
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.delete
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.patch
import java.util.UUID

@WebMvcTest
@Import(GlobalExceptionHandler::class, UsersController::class)
@AutoConfigureMockMvc(addFilters = false)
class UsersControllerTest {

    @Autowired lateinit var mockMvc: MockMvc
    @MockkBean lateinit var getUserUseCase: GetUserUseCase
    @MockkBean lateinit var updateUserUseCase: UpdateUserUseCase
    @MockkBean lateinit var changeUserStatusUseCase: ChangeUserStatusUseCase
    @MockkBean lateinit var deleteUserUseCase: DeleteUserUseCase
    @MockkBean lateinit var createUserUseCase: CreateUserUseCase

    private val testUser = User.create("test@example.com", "Test User")

    @Test
    fun `GET users-{id} returns user response`() {
        every { getUserUseCase.execute(GetUserUseCase.Query(testUser.id)) } returns testUser

        mockMvc.get("/api/v1/users/${testUser.id}")
            .andExpect {
                status { isOk() }
                jsonPath("$.success") { value(true) }
                jsonPath("$.data.email") { value("test@example.com") }
                jsonPath("$.data.displayName") { value("Test User") }
            }
    }

    @Test
    fun `GET users-{id} returns USER_NOT_FOUND for missing user`() {
        val id = UUID.randomUUID()
        every { getUserUseCase.execute(GetUserUseCase.Query(id)) } throws
            NotFoundException("User not found", ErrorCode.USER_NOT_FOUND)

        mockMvc.get("/api/v1/users/$id")
            .andExpect {
                status { isNotFound() }
                jsonPath("$.success") { value(false) }
                jsonPath("$.error.code") { value("USER_NOT_FOUND") }
            }
    }

    @Test
    fun `PATCH users-{id} updates display name`() {
        every { updateUserUseCase.execute(any()) } returns UpdateUserUseCase.Result(testUser)

        mockMvc.patch("/api/v1/users/${testUser.id}") {
            contentType = MediaType.APPLICATION_JSON
            content = """{"displayName": "Updated Name"}"""
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
        }
    }

    @Test
    fun `DELETE users-{id} returns 204`() {
        justRun { deleteUserUseCase.execute(DeleteUserUseCase.Command(testUser.id)) }

        mockMvc.delete("/api/v1/users/${testUser.id}")
            .andExpect { status { isNoContent() } }
    }
}
