package com.aibles.iam.audit

import com.aibles.iam.BaseIntegrationTest
import com.aibles.iam.identity.api.dto.CreateUserRequest
import com.fasterxml.jackson.databind.ObjectMapper
import org.hamcrest.Matchers.greaterThanOrEqualTo
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post

class AuditLogIntegrationTest : BaseIntegrationTest() {

    @Autowired lateinit var mockMvc: MockMvc
    @Autowired lateinit var objectMapper: ObjectMapper

    @Test
    fun `creating a user produces USER_CREATED audit event`() {
        val body = objectMapper.writeValueAsString(
            CreateUserRequest("audit-test@example.com", "Audit Test")
        )

        // Create a user — this should trigger a USER_CREATED audit event
        mockMvc.post("/api/v1/users") {
            with(jwt())
            contentType = MediaType.APPLICATION_JSON
            content = body
        }.andExpect { status { isCreated() } }

        // Query audit logs for USER_CREATED events
        mockMvc.get("/api/v1/audit-logs") {
            with(jwt())
            param("eventType", "USER_CREATED")
        }.andExpect {
            status { isOk() }
            jsonPath("$.success") { value(true) }
            jsonPath("$.data.totalElements", greaterThanOrEqualTo(1))
            jsonPath("$.data.content[0].eventType") { value("USER_CREATED") }
        }
    }

    @Test
    fun `audit-logs endpoint returns empty page when no events match filter`() {
        mockMvc.get("/api/v1/audit-logs") {
            with(jwt())
            param("eventType", "TOKEN_REVOKED")
        }.andExpect {
            status { isOk() }
            jsonPath("$.data.totalElements") { value(0) }
            jsonPath("$.data.content") { isEmpty() }
        }
    }
}
