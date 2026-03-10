package com.aibles.iam.authentication.infra

import com.aibles.iam.authentication.usecase.LoginWithGoogleUseCase
import com.aibles.iam.authentication.usecase.SyncGoogleUserUseCase
import com.aibles.iam.identity.domain.user.User
import com.aibles.iam.shared.config.CorsProperties
import com.aibles.iam.shared.web.HttpContextExtractor
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import io.mockk.every
import io.mockk.mockk
import org.assertj.core.api.Assertions.assertThat
import org.springframework.context.ApplicationEventPublisher
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.oidc.user.OidcUser
import org.junit.jupiter.api.Test
import java.util.UUID

class GoogleOAuth2SuccessHandlerTest {

    private val syncUseCase = mockk<SyncGoogleUserUseCase>()
    private val loginUseCase = mockk<LoginWithGoogleUseCase>()
    private val objectMapper = ObjectMapper().registerKotlinModule()
    private val eventPublisher = mockk<ApplicationEventPublisher>(relaxed = true)
    private val corsProperties = CorsProperties(frontendUrl = "http://localhost:3000")
    private val httpContextExtractor = mockk<HttpContextExtractor>(relaxed = true)

    private val handler = GoogleOAuth2SuccessHandler(
        syncGoogleUserUseCase = syncUseCase,
        loginWithGoogleUseCase = loginUseCase,
        objectMapper = objectMapper,
        eventPublisher = eventPublisher,
        corsProperties = corsProperties,
        httpContextExtractor = httpContextExtractor,
    )

    @Test
    fun `success response is HTML that calls postMessage and closes window`() {
        val userId = UUID.randomUUID()
        val mockUser = mockk<User> { every { id } returns userId; every { email } returns "u@test.com" }
        val mockOidc = mockk<OidcUser>()
        val mockAuth = mockk<Authentication> { every { principal } returns mockOidc }

        every { loginUseCase.execute(any()) } returns LoginWithGoogleUseCase.Result(
            user = mockUser,
            accessToken = "access-123",
            refreshToken = "refresh-456",
            expiresIn = 900L,
        )

        val request = MockHttpServletRequest()
        val response = MockHttpServletResponse()

        handler.onAuthenticationSuccess(request, response, mockAuth)

        assertThat(response.contentType).contains("text/html")
        val body = response.contentAsString
        assertThat(body).contains("window.opener.postMessage")
        assertThat(body).contains("access-123")
        assertThat(body).contains("refresh-456")
        assertThat(body).contains("http://localhost:3000")
        assertThat(body).contains("window.close()")
    }
}
