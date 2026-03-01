package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.MediaType
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2FailureHandler(
    private val objectMapper: ObjectMapper,
    private val eventPublisher: ApplicationEventPublisher,
) : AuthenticationFailureHandler {

    private val logger = LoggerFactory.getLogger(GoogleOAuth2FailureHandler::class.java)

    override fun onAuthenticationFailure(
        request: HttpServletRequest,
        response: HttpServletResponse,
        exception: AuthenticationException,
    ) {
        logger.warn("Google OAuth2 authentication failed: {}", exception.message)

        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.LOGIN_GOOGLE_FAILURE,
            ipAddress = request.remoteAddr,
            userAgent = request.getHeader("User-Agent"),
            metadata = mapOf("error" to exception.message),
        ))

        response.status = HttpServletResponse.SC_UNAUTHORIZED
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        objectMapper.writeValue(
            response.writer,
            ApiResponse.error("GOOGLE_AUTH_FAILED", exception.message ?: "Authentication failed"),
        )
    }
}
