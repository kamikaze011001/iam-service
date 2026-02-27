package com.aibles.iam.authentication.infra

import com.aibles.iam.authentication.api.dto.TokenResponse
import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.shared.response.ApiResponse
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.MediaType
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.stereotype.Component

@Component
class GoogleOAuth2SuccessHandler(
    private val loginWithGoogleUseCase: LoginWithGoogleUseCase,
    private val objectMapper: ObjectMapper,
) : AuthenticationSuccessHandler {

    private val requestCache = HttpSessionRequestCache()
    private val savedRequestHandler = SavedRequestAwareAuthenticationSuccessHandler()

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

        // Ensure user exists in DB for both flows
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))

        // OAuth2 AS authorization code flow: a saved request is in the session.
        // Redirect back so the AS can issue the authorization code to the client.
        val savedRequest = requestCache.getRequest(request, response)
        if (savedRequest != null) {
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication)
            return
        }

        // Direct Google login flow: write token JSON response
        val body = ApiResponse.ok(TokenResponse(result.accessToken, result.refreshToken, result.expiresIn))
        response.contentType = MediaType.APPLICATION_JSON_VALUE
        response.status = HttpServletResponse.SC_OK
        objectMapper.writeValue(response.writer, body)
    }
}
