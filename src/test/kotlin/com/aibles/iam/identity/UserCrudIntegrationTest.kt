package com.aibles.iam.identity

import com.aibles.iam.BaseIntegrationTest
import com.aibles.iam.identity.api.dto.ChangeStatusRequest
import com.aibles.iam.identity.api.dto.CreateUserRequest
import com.aibles.iam.identity.api.dto.UpdateUserRequest
import com.aibles.iam.identity.domain.user.UserStatus
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.delete
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.patch
import org.springframework.test.web.servlet.post

class UserCrudIntegrationTest : BaseIntegrationTest() {

    @Autowired lateinit var mockMvc: MockMvc
    @Autowired lateinit var objectMapper: ObjectMapper

    @Test
    fun `full user lifecycle - create, read, update, change status, delete`() {
        // CREATE
        val createBody = objectMapper.writeValueAsString(CreateUserRequest("inttest@example.com", "Test User"))
        val createResult = mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = createBody
        }.andExpect {
            status { isCreated() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.email") { value("inttest@example.com") }
            jsonPath("$.data.displayName") { value("Test User") }
            jsonPath("$.data.status") { value("ACTIVE") }
        }.andReturn()

        val userId = objectMapper.readTree(createResult.response.contentAsString)
            .at("/data/id").asText()

        // READ
        mockMvc.get("/api/v1/users/$userId") {
            with(jwt())
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.email") { value("inttest@example.com") }
        }

        // UPDATE
        val updateBody = objectMapper.writeValueAsString(UpdateUserRequest("Updated Name"))
        mockMvc.patch("/api/v1/users/$userId") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = updateBody
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.displayName") { value("Updated Name") }
        }

        // CHANGE STATUS
        val statusBody = objectMapper.writeValueAsString(ChangeStatusRequest(UserStatus.DISABLED))
        mockMvc.patch("/api/v1/users/$userId/status") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = statusBody
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.status") { value("DISABLED") }
        }

        // DELETE
        mockMvc.delete("/api/v1/users/$userId") {
            with(jwt())
        }.andExpect {
            status { isNoContent() }
        }

        // VERIFY DELETED
        mockMvc.get("/api/v1/users/$userId") {
            with(jwt())
        }.andExpect {
            status { isNotFound() }
        }
    }

    @Test
    fun `create user with duplicate email returns 409`() {
        val body = objectMapper.writeValueAsString(CreateUserRequest("duplicate@example.com", null))
        mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect { status { isCreated() } }

        mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect {
            status { isConflict() }
            jsonPath("$.error.code") { value("USER_EMAIL_CONFLICT") }
        }
    }
}
