package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.authentication.usecase.SyncGoogleUserUseCase
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2SuccessHandler(
    private val syncGoogleUserUseCase: SyncGoogleUserUseCase,
    private val loginWithGoogleUseCase: LoginWithGoogleUseCase,
    private val objectMapper: ObjectMapper,
    private val eventPublisher: ApplicationEventPublisher,
    private val requestCache: HttpSessionRequestCache = HttpSessionRequestCache(),
    private val savedRequestHandler: SavedRequestAwareAuthenticationSuccessHandler = SavedRequestAwareAuthenticationSuccessHandler(),
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val principal = authentication.principal
        if (principal !is OidcUser) {
            response.status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR
            response.contentType = MediaType.APPLICATION_JSON_VALUE
            objectMapper.writeValue(
                response.writer,
                ApiResponse.error("INTERNAL_ERROR", "Unexpected authentication principal type")
            )
            return
        }

        // Check for OAuth2 AS authorization code flow FIRST to avoid issuing tokens that
        // will be immediately discarded. The AS redirect path only needs the user to exist
        // in the DB — token issuance is handled by the AS after redirecting back.
        val savedRequest = requestCache.getRequest(request, response)
        if (savedRequest != null) {
            val result = syncGoogleUserUseCase.execute(SyncGoogleUserUseCase.Command(principal))
            eventPublisher.publishEvent(AuditDomainEvent(
                eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
                userId = result.user.id,
                actorId = result.user.id,
                metadata = mapOf("email" to result.user.email),
            ))
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication)
            return
        }

        // Direct Google login flow: upsert user + issue tokens + return JSON.
        // Note: first-time users also trigger USER_CREATED (from CreateUserUseCase), so
        // a first login produces two audit events: USER_CREATED + LOGIN_GOOGLE_SUCCESS.
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
            userId = result.user.id,
            actorId = result.user.id,
            metadata = mapOf("email" to result.user.email),
        ))
        val body = ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpServletResponse.SC_OK
        objectMapper.writeValue(response.writer, body)
    }
}
