package com.aibles.iam.authentication.infra

import com.aibles.iam.audit.domain.log.AuditDomainEvent
import com.aibles.iam.audit.domain.log.AuditEvent
import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.authentication.usecase.SyncGoogleUserUseCase
import com.aibles.iam.shared.config.CorsProperties
import com.aibles.iam.shared.web.HttpContextExtractor
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
    private val corsProperties: CorsProperties,
    private val httpContextExtractor: HttpContextExtractor,
    private val requestCache: HttpSessionRequestCache = HttpSessionRequestCache(),
    private val savedRequestHandler: SavedRequestAwareAuthenticationSuccessHandler =
        SavedRequestAwareAuthenticationSuccessHandler(),
) : AuthenticationSuccessHandler {

    override fun onAuthenticationSuccess(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authentication: Authentication,
    ) {
        val principal = authentication.principal
        if (principal !is OidcUser) {
            response.status = HttpServletResponse.SC_INTERNAL_SERVER_ERROR
            response.contentType = MediaType.TEXT_HTML_VALUE
            response.writer.write(errorHtml("Unexpected authentication principal type", corsProperties.frontendUrl))
            return
        }

        // AS authorization code flow: just sync the user and let the AS handle redirect.
        val savedRequest = requestCache.getRequest(request, response)
        if (savedRequest != null) {
            val result = syncGoogleUserUseCase.execute(SyncGoogleUserUseCase.Command(principal))
            eventPublisher.publishEvent(AuditDomainEvent(
                eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
                userId = result.user.id,
                actorId = result.user.id,
                metadata = mapOf("email" to result.user.email),
                ipAddress = httpContextExtractor.clientIp(),
                userAgent = httpContextExtractor.userAgent(),
            ))
            savedRequestHandler.onAuthenticationSuccess(request, response, authentication)
            return
        }

        // Direct Google login (popup flow): issue tokens, relay via postMessage, close popup.
        val result = loginWithGoogleUseCase.execute(LoginWithGoogleUseCase.Command(principal))
        eventPublisher.publishEvent(AuditDomainEvent(
            eventType = AuditEvent.LOGIN_GOOGLE_SUCCESS,
            userId = result.user.id,
            actorId = result.user.id,
            metadata = mapOf("email" to result.user.email),
            ipAddress = httpContextExtractor.clientIp(),
            userAgent = httpContextExtractor.userAgent(),
        ))

        response.status = HttpServletResponse.SC_OK
        response.contentType = MediaType.TEXT_HTML_VALUE
        response.writer.write(
            successHtml(
                accessToken = result.accessToken,
                refreshToken = result.refreshToken,
                expiresIn = result.expiresIn,
                targetOrigin = corsProperties.frontendUrl,
            )
        )
    }

    private fun successHtml(
        accessToken: String,
        refreshToken: String,
        expiresIn: Long,
        targetOrigin: String,
    ): String {
        // Serialize via Jackson to ensure correct JSON escaping inside the script.
        val payload = objectMapper.writeValueAsString(
            mapOf(
                "type" to "GOOGLE_AUTH_SUCCESS",
                "accessToken" to accessToken,
                "refreshToken" to refreshToken,
                "expiresIn" to expiresIn,
            )
        )
        return """
            <!DOCTYPE html>
            <html>
            <head><title>Authenticating…</title></head>
            <body>
            <script>
              (function() {
                var payload = $payload;
                var origin  = ${objectMapper.writeValueAsString(targetOrigin)};
                if (window.opener) {
                  window.opener.postMessage(payload, origin);
                }
                window.close();
              })();
            </script>
            <p>Authentication complete. This window will close automatically.</p>
            </body>
            </html>
        """.trimIndent()
    }

    private fun errorHtml(message: String, targetOrigin: String): String = """
        <!DOCTYPE html><html><body>
        <script>
          if (window.opener) {
            window.opener.postMessage({type:'GOOGLE_AUTH_ERROR',message:${objectMapper.writeValueAsString(message)}}, ${objectMapper.writeValueAsString(targetOrigin)});
          }
          window.close();
        </script>
        <p>Authentication failed: $message</p>
        </body></html>
    """.trimIndent()
}
