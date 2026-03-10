package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.shared.web.HttpContextExtractor
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.context.ApplicationEventPublisher
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.BadCredentialsException

class GoogleOAuth2FailureHandlerTest {

    private val objectMapper: ObjectMapper = jacksonObjectMapper().registerModule(JavaTimeModule())
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val httpContextExtractor = mockk<HttpContextExtractor>(relaxed = true)
    private val handler = GoogleOAuth2FailureHandler(objectMapper, eventPublisher, httpContextExtractor)

    @Test
    fun `onAuthenticationFailure publishes LOGIN_GOOGLE_FAILURE and returns 401`() {
        every { httpContextExtractor.clientIp() } returns "10.0.0.1"
        every { httpContextExtractor.userAgent() } returns "TestBrowser"

        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()
        val exception = BadCredentialsException("Invalid token")

        handler.onAuthenticationFailure(request, response, exception)

        // Verify audit event
        val captured = slot<AuditDomainEvent>()
        verify(exactly = 1) { eventPublisher.publishEvent(capture(captured)) }
        assertThat(captured.captured.eventType).isEqualTo(AuditEvent.LOGIN_GOOGLE_FAILURE)
        assertThat(captured.captured.ipAddress).isEqualTo("10.0.0.1")
        assertThat(captured.captured.userAgent).isEqualTo("TestBrowser")
        assertThat(captured.captured.metadata).containsEntry("error", "Invalid token")

        // Verify HTTP response
        assertThat(response.status).isEqualTo(401)
        assertThat(response.contentType).isEqualTo("application/json")
        assertThat(response.contentAsString).contains("GOOGLE_AUTH_FAILED")
    }

    @Test
    fun `onAuthenticationFailure handles null user-agent`() {
        every { httpContextExtractor.clientIp() } returns null
        every { httpContextExtractor.userAgent() } returns null

        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()
        val exception = BadCredentialsException("Denied")

        handler.onAuthenticationFailure(request, response, exception)

        val captured = slot<AuditDomainEvent>()
        verify(exactly = 1) { eventPublisher.publishEvent(capture(captured)) }
        assertThat(captured.captured.userAgent).isNull()
        assertThat(response.status).isEqualTo(401)
    }
}
